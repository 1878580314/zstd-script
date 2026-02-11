use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::rand_core::RngCore;
use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use walkdir::WalkDir;

const IO_BUFFER_SIZE: usize = 8 * 1024 * 1024;
const MIB: f64 = 1024.0 * 1024.0;
const PROGRESS_EVENT: &str = "zarc://progress";
const PROGRESS_EMIT_INTERVAL: Duration = Duration::from_millis(120);

const ENC_MAGIC: &[u8; 8] = b"ZENC0001";
const ENC_SALT_LEN: usize = 16;
const ENC_NONCE_PREFIX_LEN: usize = 16;
const ENC_KEY_LEN: usize = 32;
const ENC_CHUNK_SIZE: usize = 256 * 1024;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompressRequest {
    source_path: String,
    output_path: Option<String>,
    level: Option<i32>,
    include_root_dir: Option<bool>,
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecompressRequest {
    archive_path: String,
    output_path: Option<String>,
    password: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct BenchmarkRequest {
    source_path: String,
    min_level: Option<u8>,
    max_level: Option<u8>,
    iterations: Option<u32>,
    sample_size_mib: Option<u32>,
    threads: Option<u32>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct OperationReport {
    operation: String,
    source_path: String,
    output_path: String,
    source_bytes: u64,
    output_bytes: u64,
    duration_ms: f64,
    throughput_mi_bs: f64,
    compression_ratio: Option<f64>,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct CompressionLevelReport {
    level: u8,
    mean_ms: f64,
    mean_throughput_mi_bs: f64,
    compressed_bytes: u64,
    ratio_percent: f64,
    score: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BenchmarkReport {
    source_path: String,
    sample_bytes: u64,
    min_level: u8,
    max_level: u8,
    iterations: u32,
    threads: u32,
    recommended_level: u8,
    results: Vec<CompressionLevelReport>,
    note: String,
}

#[derive(Debug, Serialize, Clone)]
#[serde(rename_all = "camelCase")]
struct ProgressPayload {
    operation: String,
    processed_bytes: u64,
    total_bytes: u64,
    percent: f64,
    throughput_mi_bs: f64,
    eta_seconds: Option<f64>,
    done: bool,
    error: Option<String>,
}

#[derive(Debug, Copy, Clone)]
enum ArchiveKind {
    TarZst,
    Zst,
}

#[derive(Debug, Copy, Clone)]
struct ArchiveMeta {
    kind: ArchiveKind,
    encrypted: bool,
}

struct ProgressState {
    started: Instant,
    processed: AtomicU64,
    last_emit: Mutex<Instant>,
}

#[derive(Clone)]
struct ProgressReporter {
    app: Option<AppHandle>,
    operation: &'static str,
    total: u64,
    state: Arc<ProgressState>,
}

impl ProgressReporter {
    fn new(app: Option<AppHandle>, operation: &'static str, total: u64) -> Self {
        let now = Instant::now();
        Self {
            app,
            operation,
            total,
            state: Arc::new(ProgressState {
                started: now,
                processed: AtomicU64::new(0),
                last_emit: Mutex::new(now - PROGRESS_EMIT_INTERVAL),
            }),
        }
    }

    fn begin(&self) {
        self.emit(false, None, true);
    }

    fn advance(&self, delta: u64) {
        if delta > 0 {
            self.state
                .processed
                .fetch_add(delta, AtomicOrdering::Relaxed);
            self.emit(false, None, false);
        }
    }

    fn finish(&self) {
        self.state
            .processed
            .store(self.total, AtomicOrdering::Relaxed);
        self.emit(true, None, true);
    }

    fn fail(&self, message: String) {
        self.emit(true, Some(message), true);
    }

    fn emit(&self, done: bool, error: Option<String>, force: bool) {
        if self.app.is_none() {
            return;
        }

        {
            let mut last_emit = self
                .state
                .last_emit
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            if !force && !done && last_emit.elapsed() < PROGRESS_EMIT_INTERVAL {
                return;
            }
            *last_emit = Instant::now();
        }

        let processed = self
            .state
            .processed
            .load(AtomicOrdering::Relaxed)
            .min(self.total);

        let elapsed = self.state.started.elapsed().as_secs_f64().max(f64::EPSILON);
        let throughput = throughput(processed, elapsed);
        let percent = if self.total == 0 {
            100.0
        } else {
            processed as f64 / self.total as f64 * 100.0
        };

        let eta_seconds = if done || throughput <= 0.0 || processed >= self.total {
            None
        } else {
            let remaining_mib = (self.total.saturating_sub(processed) as f64) / MIB;
            Some(remaining_mib / throughput)
        };

        let payload = ProgressPayload {
            operation: self.operation.to_string(),
            processed_bytes: processed,
            total_bytes: self.total,
            percent: percent.clamp(0.0, 100.0),
            throughput_mi_bs: throughput,
            eta_seconds,
            done,
            error,
        };

        if let Some(app) = &self.app {
            let _ = app.emit(PROGRESS_EVENT, payload);
        }
    }
}

struct ProgressReader<R> {
    inner: R,
    reporter: ProgressReporter,
}

impl<R> ProgressReader<R> {
    fn new(inner: R, reporter: ProgressReporter) -> Self {
        Self { inner, reporter }
    }
}

impl<R: Read> Read for ProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let count = self.inner.read(buf)?;
        if count > 0 {
            self.reporter.advance(count as u64);
        }
        Ok(count)
    }
}

struct CountingWriter<W> {
    inner: W,
    written: u64,
}

impl<W> CountingWriter<W> {
    fn new(inner: W) -> Self {
        Self { inner, written: 0 }
    }

    fn written(&self) -> u64 {
        self.written
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let count = self.inner.write(buf)?;
        self.written = self.written.saturating_add(count as u64);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

enum OutputSink {
    Plain(BufWriter<File>),
    Encrypted(EncryptedWriter<BufWriter<File>>),
}

impl OutputSink {
    fn finalize(self) -> Result<()> {
        match self {
            Self::Plain(mut writer) => {
                writer.flush().context("刷新输出文件失败")?;
            }
            Self::Encrypted(writer) => {
                writer.finish().context("完成加密输出失败")?;
            }
        }
        Ok(())
    }
}

impl Write for OutputSink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(writer) => writer.write(buf),
            Self::Encrypted(writer) => writer.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Encrypted(writer) => writer.flush(),
        }
    }
}

struct EncryptedWriter<W: Write> {
    inner: W,
    cipher: XChaCha20Poly1305,
    nonce_prefix: [u8; ENC_NONCE_PREFIX_LEN],
    counter: u64,
    buffer: Vec<u8>,
    finished: bool,
}

impl<W: Write> EncryptedWriter<W> {
    fn new(mut inner: W, password: &str) -> Result<Self> {
        let mut salt = [0_u8; ENC_SALT_LEN];
        let mut nonce_prefix = [0_u8; ENC_NONCE_PREFIX_LEN];
        OsRng.fill_bytes(&mut salt);
        OsRng.fill_bytes(&mut nonce_prefix);

        let key = derive_encryption_key(password, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));

        inner
            .write_all(ENC_MAGIC)
            .context("写入加密头失败: magic")?;
        inner.write_all(&salt).context("写入加密头失败: salt")?;
        inner
            .write_all(&nonce_prefix)
            .context("写入加密头失败: nonce prefix")?;

        Ok(Self {
            inner,
            cipher,
            nonce_prefix,
            counter: 0,
            buffer: Vec::with_capacity(ENC_CHUNK_SIZE),
            finished: false,
        })
    }

    fn write_encrypted_chunk(&mut self, plain: &[u8]) -> io::Result<()> {
        let nonce = make_nonce(self.nonce_prefix, self.counter);
        self.counter = self.counter.saturating_add(1);

        let cipher_text = self
            .cipher
            .encrypt(XNonce::from_slice(&nonce), plain)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "加密失败"))?;

        let len = cipher_text.len() as u32;
        self.inner.write_all(&len.to_be_bytes())?;
        self.inner.write_all(&cipher_text)?;
        Ok(())
    }

    fn finish(mut self) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }

        if !self.buffer.is_empty() {
            let buffer = std::mem::take(&mut self.buffer);
            self.write_encrypted_chunk(&buffer)?;
        }

        self.inner.write_all(&0_u32.to_be_bytes())?;
        self.inner.flush()?;
        self.finished = true;
        Ok(())
    }
}

impl<W: Write> Write for EncryptedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.finished {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "加密写入器已结束",
            ));
        }

        self.buffer.extend_from_slice(buf);

        while self.buffer.len() >= ENC_CHUNK_SIZE {
            let chunk = self.buffer[..ENC_CHUNK_SIZE].to_vec();
            self.write_encrypted_chunk(&chunk)?;
            self.buffer.drain(..ENC_CHUNK_SIZE);
        }

        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

struct EncryptedReader<R: Read> {
    inner: R,
    cipher: XChaCha20Poly1305,
    nonce_prefix: [u8; ENC_NONCE_PREFIX_LEN],
    counter: u64,
    decrypted: Vec<u8>,
    pos: usize,
    eof: bool,
}

impl<R: Read> EncryptedReader<R> {
    fn new(mut inner: R, password: &str) -> Result<Self> {
        let mut magic = [0_u8; ENC_MAGIC.len()];
        inner
            .read_exact(&mut magic)
            .context("读取加密头失败: magic")?;
        if &magic != ENC_MAGIC {
            bail!("无效加密文件头，无法识别的归档格式");
        }

        let mut salt = [0_u8; ENC_SALT_LEN];
        let mut nonce_prefix = [0_u8; ENC_NONCE_PREFIX_LEN];
        inner
            .read_exact(&mut salt)
            .context("读取加密头失败: salt")?;
        inner
            .read_exact(&mut nonce_prefix)
            .context("读取加密头失败: nonce prefix")?;

        let key = derive_encryption_key(password, &salt)?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(&key));

        Ok(Self {
            inner,
            cipher,
            nonce_prefix,
            counter: 0,
            decrypted: Vec::new(),
            pos: 0,
            eof: false,
        })
    }

    fn read_next_chunk(&mut self) -> io::Result<()> {
        if self.eof {
            return Ok(());
        }

        let mut len_buf = [0_u8; 4];
        self.inner.read_exact(&mut len_buf)?;
        let chunk_len = u32::from_be_bytes(len_buf) as usize;
        if chunk_len == 0 {
            self.eof = true;
            self.decrypted.clear();
            self.pos = 0;
            return Ok(());
        }

        let mut cipher_text = vec![0_u8; chunk_len];
        self.inner.read_exact(&mut cipher_text)?;

        let nonce = make_nonce(self.nonce_prefix, self.counter);
        self.counter = self.counter.saturating_add(1);

        let plain = self
            .cipher
            .decrypt(XNonce::from_slice(&nonce), cipher_text.as_ref())
            .map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "解密失败：密码错误或文件已损坏")
            })?;

        self.decrypted = plain;
        self.pos = 0;
        Ok(())
    }
}

impl<R: Read> Read for EncryptedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut written = 0_usize;
        while written < buf.len() {
            if self.pos >= self.decrypted.len() {
                self.read_next_chunk()?;
                if self.eof {
                    break;
                }
            }

            let available = self.decrypted.len().saturating_sub(self.pos);
            if available == 0 {
                break;
            }

            let take = (buf.len() - written).min(available);
            buf[written..written + take]
                .copy_from_slice(&self.decrypted[self.pos..self.pos + take]);
            self.pos += take;
            written += take;
        }

        Ok(written)
    }
}

#[tauri::command]
async fn compress_archive(
    app: AppHandle,
    request: CompressRequest,
) -> std::result::Result<OperationReport, String> {
    tauri::async_runtime::spawn_blocking(move || compress_archive_sync(request, Some(app)))
        .await
        .map_err(|err| format!("任务线程异常: {err}"))?
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn decompress_archive(
    app: AppHandle,
    request: DecompressRequest,
) -> std::result::Result<OperationReport, String> {
    tauri::async_runtime::spawn_blocking(move || decompress_archive_sync(request, Some(app)))
        .await
        .map_err(|err| format!("任务线程异常: {err}"))?
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn benchmark_compression(
    request: BenchmarkRequest,
) -> std::result::Result<BenchmarkReport, String> {
    tauri::async_runtime::spawn_blocking(move || benchmark_compression_sync(request))
        .await
        .map_err(|err| format!("任务线程异常: {err}"))?
        .map_err(|err| err.to_string())
}

fn compress_archive_sync(
    request: CompressRequest,
    app: Option<AppHandle>,
) -> Result<OperationReport> {
    let source = PathBuf::from(request.source_path.trim());
    if !source.exists() {
        bail!("源路径不存在: {}", source.display());
    }

    let level = request.level.unwrap_or(8).clamp(1, 22);
    let include_root_dir = request.include_root_dir.unwrap_or(true);
    let password = normalize_password(request.password);
    let source_bytes = count_source_bytes(&source)?;
    let output =
        resolve_compress_output(&source, request.output_path.as_deref(), password.is_some())?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("无法创建输出目录: {}", parent.display()))?;
    }

    let reporter = ProgressReporter::new(app, "compress", source_bytes);
    reporter.begin();

    let started = Instant::now();
    let operation_result = if source.is_dir() {
        compress_directory(
            &source,
            &output,
            level,
            include_root_dir,
            password.as_deref(),
            &reporter,
        )
    } else {
        compress_file(&source, &output, level, password.as_deref(), &reporter)
    };

    if let Err(err) = operation_result {
        let _ = fs::remove_file(&output);
        reporter.fail(err.to_string());
        return Err(err);
    }

    reporter.finish();

    let duration = started.elapsed().as_secs_f64();
    let output_bytes = fs::metadata(&output)
        .with_context(|| format!("无法读取结果文件信息: {}", output.display()))?
        .len();

    Ok(OperationReport {
        operation: "compress".to_string(),
        source_path: path_to_string(&source),
        output_path: path_to_string(&output),
        source_bytes,
        output_bytes,
        duration_ms: duration * 1000.0,
        throughput_mi_bs: throughput(source_bytes, duration),
        compression_ratio: Some(ratio(output_bytes, source_bytes)),
    })
}

fn decompress_archive_sync(
    request: DecompressRequest,
    app: Option<AppHandle>,
) -> Result<OperationReport> {
    let archive = PathBuf::from(request.archive_path.trim());
    if !archive.exists() {
        bail!("归档文件不存在: {}", archive.display());
    }

    let meta = detect_archive_meta(&archive)?;
    let password = normalize_password(request.password);
    if meta.encrypted && password.is_none() {
        bail!("该归档已加密，请提供解密密码");
    }

    let source_bytes = fs::metadata(&archive)
        .with_context(|| format!("无法读取归档信息: {}", archive.display()))?
        .len();

    let output = resolve_decompress_output(&archive, meta, request.output_path.as_deref())?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("无法创建输出目录: {}", parent.display()))?;
    }

    let reporter = ProgressReporter::new(app, "decompress", source_bytes);
    reporter.begin();

    let started = Instant::now();

    let input =
        File::open(&archive).with_context(|| format!("无法打开归档文件: {}", archive.display()))?;
    let reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let progress_reader = ProgressReader::new(reader, reporter.clone());

    let output_bytes = match (meta.encrypted, meta.kind) {
        (true, ArchiveKind::TarZst) => {
            fs::create_dir_all(&output)
                .with_context(|| format!("无法创建解压目录: {}", output.display()))?;
            let decrypt_reader =
                EncryptedReader::new(progress_reader, password.as_deref().unwrap_or_default())?;
            decompress_tar_from_reader(decrypt_reader, &output)?;
            count_source_bytes(&output)?
        }
        (true, ArchiveKind::Zst) => {
            let decrypt_reader =
                EncryptedReader::new(progress_reader, password.as_deref().unwrap_or_default())?;
            decompress_file_from_reader(decrypt_reader, &output)?
        }
        (false, ArchiveKind::TarZst) => {
            fs::create_dir_all(&output)
                .with_context(|| format!("无法创建解压目录: {}", output.display()))?;
            decompress_tar_from_reader(progress_reader, &output)?;
            count_source_bytes(&output)?
        }
        (false, ArchiveKind::Zst) => decompress_file_from_reader(progress_reader, &output)?,
    };

    reporter.finish();

    let duration = started.elapsed().as_secs_f64();

    Ok(OperationReport {
        operation: "decompress".to_string(),
        source_path: path_to_string(&archive),
        output_path: path_to_string(&output),
        source_bytes,
        output_bytes,
        duration_ms: duration * 1000.0,
        throughput_mi_bs: throughput(output_bytes.max(source_bytes), duration),
        compression_ratio: None,
    })
}

fn benchmark_compression_sync(request: BenchmarkRequest) -> Result<BenchmarkReport> {
    let source = PathBuf::from(request.source_path.trim());
    if !source.exists() {
        bail!("源路径不存在: {}", source.display());
    }

    let mut min_level = request.min_level.unwrap_or(1).clamp(1, 22);
    let mut max_level = request.max_level.unwrap_or(12).clamp(1, 22);
    if min_level > max_level {
        std::mem::swap(&mut min_level, &mut max_level);
    }

    let iterations = request.iterations.unwrap_or(2).clamp(1, 12);
    let sample_size_mib = request.sample_size_mib.unwrap_or(64).clamp(4, 1024);
    let sample_limit = sample_size_mib as usize * 1024 * 1024;

    let cpu_threads = num_cpus::get().max(1) as u32;
    let threads = request
        .threads
        .unwrap_or(cpu_threads)
        .clamp(1, cpu_threads.max(1));

    let sample = load_benchmark_sample(&source, sample_limit)?;
    if sample.is_empty() {
        bail!("基准测试样本为空，无法评估压缩等级");
    }

    let sample_bytes = sample.len() as u64;
    let mut results = Vec::new();

    for level in min_level..=max_level {
        let mut ms_samples = Vec::with_capacity(iterations as usize);
        let mut throughput_samples = Vec::with_capacity(iterations as usize);
        let mut compressed_bytes = 0_u64;

        for _ in 0..iterations {
            let start = Instant::now();
            compressed_bytes = compress_to_count(&sample, level as i32, threads)?;
            let elapsed = start.elapsed().as_secs_f64();

            ms_samples.push(elapsed * 1000.0);
            throughput_samples.push(throughput(sample_bytes, elapsed));
        }

        results.push(CompressionLevelReport {
            level,
            mean_ms: mean(&ms_samples),
            mean_throughput_mi_bs: mean(&throughput_samples),
            compressed_bytes,
            ratio_percent: ratio(compressed_bytes, sample_bytes),
            score: 0.0,
        });
    }

    apply_score(&mut results);
    let recommended_level = choose_recommended_level(&results)
        .with_context(|| "无法从 benchmark 结果中推导推荐等级")?;

    let note = format!(
        "基于样本大小约 {:.2} MiB 的快速压缩测试。推荐等级已平衡压缩率与吞吐。",
        sample_bytes as f64 / MIB
    );

    Ok(BenchmarkReport {
        source_path: path_to_string(&source),
        sample_bytes,
        min_level,
        max_level,
        iterations,
        threads,
        recommended_level,
        results,
        note,
    })
}

fn derive_encryption_key(password: &str, salt: &[u8; ENC_SALT_LEN]) -> Result<[u8; ENC_KEY_LEN]> {
    let mut key = [0_u8; ENC_KEY_LEN];

    let params = Params::new(32 * 1024, 2, 1, Some(ENC_KEY_LEN))
        .map_err(|err| anyhow!("创建 Argon2 参数失败: {err}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|err| anyhow!("密码派生失败: {err}"))?;

    Ok(key)
}

fn make_nonce(prefix: [u8; ENC_NONCE_PREFIX_LEN], counter: u64) -> [u8; 24] {
    let mut nonce = [0_u8; 24];
    nonce[..ENC_NONCE_PREFIX_LEN].copy_from_slice(&prefix);
    nonce[ENC_NONCE_PREFIX_LEN..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn create_output_sink(path: &Path, password: Option<&str>) -> Result<OutputSink> {
    let file =
        File::create(path).with_context(|| format!("无法创建输出文件: {}", path.display()))?;
    let writer = BufWriter::with_capacity(IO_BUFFER_SIZE, file);

    match password {
        Some(pwd) => Ok(OutputSink::Encrypted(EncryptedWriter::new(writer, pwd)?)),
        None => Ok(OutputSink::Plain(writer)),
    }
}

fn compress_to_count(data: &[u8], level: i32, threads: u32) -> Result<u64> {
    let sink = CountingWriter::new(io::sink());
    let mut encoder = zstd::Encoder::new(sink, level).context("创建 zstd 编码器失败")?;
    encoder
        .multithread(threads)
        .context("无法开启 zstd 多线程压缩")?;

    encoder
        .write_all(data)
        .context("写入压缩样本失败，无法完成快速测试")?;

    let mut sink = encoder.finish().context("无法完成压缩编码")?;
    sink.flush().context("刷新压缩输出失败")?;

    Ok(sink.written())
}

fn load_benchmark_sample(source: &Path, max_bytes: usize) -> Result<Vec<u8>> {
    let mut sample = Vec::new();
    if max_bytes == 0 {
        return Ok(sample);
    }

    if source.is_file() {
        let file = File::open(source)
            .with_context(|| format!("无法读取基准测试源文件: {}", source.display()))?;
        let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);
        read_into_sample(&mut reader, &mut sample, max_bytes)?;
        return Ok(sample);
    }

    for entry in WalkDir::new(source)
        .min_depth(1)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if !entry.file_type().is_file() {
            continue;
        }

        let file_path = entry.path();
        let file = File::open(file_path)
            .with_context(|| format!("无法读取目录样本文件: {}", file_path.display()))?;
        let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);
        read_into_sample(&mut reader, &mut sample, max_bytes)?;

        if sample.len() >= max_bytes {
            break;
        }
    }

    Ok(sample)
}

fn read_into_sample<R: Read>(reader: &mut R, sample: &mut Vec<u8>, max_bytes: usize) -> Result<()> {
    let mut buffer = vec![0_u8; 256 * 1024];

    while sample.len() < max_bytes {
        let remaining = max_bytes - sample.len();
        let read_size = remaining.min(buffer.len());
        let count = reader
            .read(&mut buffer[..read_size])
            .context("读取 benchmark 样本失败")?;
        if count == 0 {
            break;
        }
        sample.extend_from_slice(&buffer[..count]);
    }

    Ok(())
}

fn apply_score(results: &mut [CompressionLevelReport]) {
    if results.is_empty() {
        return;
    }

    let max_throughput = results
        .iter()
        .map(|item| item.mean_throughput_mi_bs)
        .fold(0.0_f64, f64::max)
        .max(f64::EPSILON);

    let min_ratio = results
        .iter()
        .map(|item| item.ratio_percent)
        .fold(f64::INFINITY, f64::min)
        .max(f64::EPSILON);

    for item in results.iter_mut() {
        let speed_score = item.mean_throughput_mi_bs / max_throughput;
        let ratio_score = min_ratio / item.ratio_percent.max(f64::EPSILON);
        item.score = speed_score * 0.45 + ratio_score * 0.55;
    }
}

fn choose_recommended_level(results: &[CompressionLevelReport]) -> Option<u8> {
    let mut iter = results.iter();
    let mut best = iter.next()?;

    for item in iter {
        let better_score = item.score > best.score + 1e-9;
        let same_score = (item.score - best.score).abs() <= 1e-9;
        let better_level = item.level < best.level;

        if better_score || (same_score && better_level) {
            best = item;
        }
    }

    Some(best.level)
}

fn compress_file(
    source: &Path,
    output: &Path,
    level: i32,
    password: Option<&str>,
    reporter: &ProgressReporter,
) -> Result<()> {
    let input =
        File::open(source).with_context(|| format!("无法打开源文件: {}", source.display()))?;
    let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);

    let output_sink = create_output_sink(output, password)?;
    let mut encoder = zstd::Encoder::new(output_sink, level).context("创建 zstd 编码器失败")?;

    let threads = num_cpus::get().max(1) as u32;
    encoder
        .multithread(threads)
        .context("无法开启 zstd 多线程压缩")?;

    let mut buf = vec![0_u8; 512 * 1024];
    loop {
        let count = reader.read(&mut buf).context("读取压缩源文件失败")?;
        if count == 0 {
            break;
        }

        encoder
            .write_all(&buf[..count])
            .context("压缩过程中写入失败")?;
        reporter.advance(count as u64);
    }

    let sink = encoder.finish().context("无法完成压缩输出")?;
    sink.finalize()?;

    Ok(())
}

fn compress_directory(
    source: &Path,
    output: &Path,
    level: i32,
    include_root_dir: bool,
    password: Option<&str>,
    reporter: &ProgressReporter,
) -> Result<()> {
    let output_sink = create_output_sink(output, password)?;
    let mut encoder = zstd::Encoder::new(output_sink, level).context("创建 zstd 编码器失败")?;

    let threads = num_cpus::get().max(1) as u32;
    encoder
        .multithread(threads)
        .context("无法开启 zstd 多线程压缩")?;

    let mut tar_builder = tar::Builder::new(encoder);
    let root_name = source
        .file_name()
        .map(|v| v.to_owned())
        .with_context(|| format!("目录名称无效: {}", source.display()))?;

    if include_root_dir {
        tar_builder
            .append_dir(Path::new(&root_name), source)
            .with_context(|| format!("写入根目录失败: {}", source.display()))?;
    }

    for entry in WalkDir::new(source)
        .min_depth(1)
        .sort_by_file_name()
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        let path = entry.path();
        let rel = path
            .strip_prefix(source)
            .with_context(|| format!("无法计算相对路径: {}", path.display()))?;

        let archive_name = if include_root_dir {
            Path::new(&root_name).join(rel)
        } else {
            rel.to_path_buf()
        };

        if entry.file_type().is_dir() {
            tar_builder
                .append_dir(&archive_name, path)
                .with_context(|| format!("写入目录失败: {}", path.display()))?;
            continue;
        }

        if entry.file_type().is_file() {
            append_file_with_progress(&mut tar_builder, path, &archive_name, reporter)?;
        }
    }

    tar_builder.finish().context("tar 归档收尾失败")?;
    let encoder = tar_builder.into_inner().context("无法获取压缩编码器")?;
    let sink = encoder.finish().context("无法完成目录压缩输出")?;
    sink.finalize()?;

    Ok(())
}

fn append_file_with_progress<W: Write>(
    tar_builder: &mut tar::Builder<W>,
    source_path: &Path,
    archive_name: &Path,
    reporter: &ProgressReporter,
) -> Result<()> {
    let file = File::open(source_path)
        .with_context(|| format!("无法读取待归档文件: {}", source_path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("无法读取文件元数据: {}", source_path.display()))?;

    let mut header = tar::Header::new_gnu();
    header.set_metadata(&metadata);
    header.set_cksum();

    let reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);
    let mut progress_reader = ProgressReader::new(reader, reporter.clone());

    tar_builder
        .append_data(&mut header, archive_name, &mut progress_reader)
        .with_context(|| format!("写入文件失败: {}", source_path.display()))?;

    Ok(())
}

fn decompress_tar_from_reader<R: Read>(reader: R, output_dir: &Path) -> Result<()> {
    let decoder = zstd::Decoder::new(reader).context("创建 zstd 解码器失败")?;
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(output_dir)
        .with_context(|| format!("解包归档失败: {}", output_dir.display()))?;
    Ok(())
}

fn decompress_file_from_reader<R: Read>(reader: R, output_file: &Path) -> Result<u64> {
    let mut decoder = zstd::Decoder::new(reader).context("创建 zstd 解码器失败")?;

    let output = File::create(output_file)
        .with_context(|| format!("无法创建输出文件: {}", output_file.display()))?;
    let mut writer = BufWriter::with_capacity(IO_BUFFER_SIZE, output);

    let mut output_bytes = 0_u64;
    let mut buffer = vec![0_u8; 512 * 1024];
    loop {
        let count = decoder.read(&mut buffer).context("解压读取失败")?;
        if count == 0 {
            break;
        }

        writer
            .write_all(&buffer[..count])
            .context("写入解压输出失败")?;
        output_bytes = output_bytes.saturating_add(count as u64);
    }

    writer.flush().context("解压结果刷盘失败")?;

    Ok(output_bytes)
}

fn detect_archive_meta(path: &Path) -> Result<ArchiveMeta> {
    let name = path
        .file_name()
        .map(|v| v.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    let encrypted = name.ends_with(".enc");
    let base = if encrypted {
        name.strip_suffix(".enc").unwrap_or(&name)
    } else {
        &name
    };

    let kind = if base.ends_with(".tar.zst") {
        ArchiveKind::TarZst
    } else if base.ends_with(".zst") {
        ArchiveKind::Zst
    } else {
        bail!("不支持的文件类型，仅支持 .zst/.tar.zst 及其 .enc 加密版本")
    };

    Ok(ArchiveMeta { kind, encrypted })
}

fn resolve_compress_output(
    source: &Path,
    output: Option<&str>,
    encrypted: bool,
) -> Result<PathBuf> {
    let mut candidate = if let Some(path) = output {
        let provided = PathBuf::from(path.trim());
        if provided.exists() && provided.is_dir() {
            provided.join(default_compress_file_name(source, encrypted)?)
        } else {
            provided
        }
    } else {
        let parent = source.parent().unwrap_or_else(|| Path::new("."));
        parent.join(default_compress_file_name(source, encrypted)?)
    };

    if encrypted {
        candidate = ensure_enc_suffix(candidate);
    }

    Ok(candidate)
}

fn ensure_enc_suffix(path: PathBuf) -> PathBuf {
    let name_lower = path
        .file_name()
        .map(|v| v.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if name_lower.ends_with(".enc") {
        return path;
    }

    let file_name = path
        .file_name()
        .map(|v| v.to_string_lossy().to_string())
        .unwrap_or_else(|| "archive".to_string());

    path.with_file_name(format!("{file_name}.enc"))
}

fn default_compress_file_name(source: &Path, encrypted: bool) -> Result<String> {
    let source_name = source
        .file_name()
        .with_context(|| format!("无效路径: {}", source.display()))?
        .to_string_lossy();

    let mut name = if source.is_dir() {
        format!("{source_name}.tar.zst")
    } else {
        format!("{source_name}.zst")
    };

    if encrypted {
        name.push_str(".enc");
    }

    Ok(name)
}

fn resolve_decompress_output(
    archive: &Path,
    meta: ArchiveMeta,
    output: Option<&str>,
) -> Result<PathBuf> {
    let default_name = default_decompress_name(archive, meta)?;

    match output {
        Some(path) => {
            let candidate = PathBuf::from(path.trim());
            match meta.kind {
                ArchiveKind::TarZst => Ok(candidate),
                ArchiveKind::Zst => {
                    if candidate.exists() && candidate.is_dir() {
                        Ok(candidate.join(default_name))
                    } else {
                        Ok(candidate)
                    }
                }
            }
        }
        None => {
            let parent = archive.parent().unwrap_or_else(|| Path::new("."));
            Ok(parent.join(default_name))
        }
    }
}

fn default_decompress_name(archive: &Path, meta: ArchiveMeta) -> Result<String> {
    let file_name = archive
        .file_name()
        .with_context(|| format!("无效路径: {}", archive.display()))?
        .to_string_lossy();

    let base = if meta.encrypted {
        file_name.trim_end_matches(".enc").to_string()
    } else {
        file_name.to_string()
    };

    match meta.kind {
        ArchiveKind::TarZst => {
            let stem = base.trim_end_matches(".tar.zst");
            Ok(format!("{stem}_extracted"))
        }
        ArchiveKind::Zst => {
            let stem = base.trim_end_matches(".zst");
            Ok(stem.to_string())
        }
    }
}

fn normalize_password(raw: Option<String>) -> Option<String> {
    raw.and_then(|value| {
        let trimmed = value.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn count_source_bytes(path: &Path) -> Result<u64> {
    if path.is_file() {
        return Ok(fs::metadata(path)
            .with_context(|| format!("无法读取文件信息: {}", path.display()))?
            .len());
    }

    let mut total = 0_u64;
    for entry in WalkDir::new(path)
        .into_iter()
        .filter_map(std::result::Result::ok)
    {
        if entry.file_type().is_file() {
            total = total.saturating_add(entry.metadata().map(|m| m.len()).unwrap_or(0));
        }
    }

    Ok(total)
}

fn throughput(bytes: u64, secs: f64) -> f64 {
    let safe_secs = secs.max(f64::EPSILON);
    (bytes as f64 / MIB) / safe_secs
}

fn ratio(output_bytes: u64, source_bytes: u64) -> f64 {
    if source_bytes == 0 {
        return 0.0;
    }
    output_bytes as f64 / source_bytes as f64 * 100.0
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            compress_archive,
            decompress_archive,
            benchmark_compression
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn deterministic_bytes(size: usize) -> Vec<u8> {
        (0..size).map(|i| ((i * 131 + 17) % 251) as u8).collect()
    }

    fn write_file(path: &Path, bytes: &[u8]) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, bytes).expect("write file");
    }

    fn collect_file_map(root: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut map = BTreeMap::new();
        for entry in WalkDir::new(root)
            .min_depth(1)
            .into_iter()
            .filter_map(std::result::Result::ok)
        {
            if !entry.file_type().is_file() {
                continue;
            }

            let rel = entry
                .path()
                .strip_prefix(root)
                .expect("strip prefix")
                .to_string_lossy()
                .replace('\\', "/");

            map.insert(rel, fs::read(entry.path()).expect("read file"));
        }
        map
    }

    fn assert_dirs_equal(expected: &Path, actual: &Path) {
        assert_eq!(collect_file_map(expected), collect_file_map(actual));
    }

    #[test]
    fn encrypted_roundtrip_file_sizes_and_types() {
        let sizes = [
            0_usize,
            1,
            31,
            4 * 1024,
            ENC_CHUNK_SIZE - 1,
            ENC_CHUNK_SIZE,
            ENC_CHUNK_SIZE + 1,
            ENC_CHUNK_SIZE * 3 + 123,
        ];

        for (idx, size) in sizes.into_iter().enumerate() {
            let temp = tempfile::tempdir().expect("temp dir");
            let source = temp.path().join(format!("data_{idx}.bin"));
            let archive = temp.path().join(format!("data_{idx}.zst.enc"));
            let output = temp.path().join(format!("out_{idx}.bin"));

            let payload = deterministic_bytes(size);
            write_file(&source, &payload);

            compress_archive_sync(
                CompressRequest {
                    source_path: path_to_string(&source),
                    output_path: Some(path_to_string(&archive)),
                    level: Some(8),
                    include_root_dir: Some(true),
                    password: Some("Strong#Pass123".to_string()),
                },
                None,
            )
            .expect("compress encrypted");

            decompress_archive_sync(
                DecompressRequest {
                    archive_path: path_to_string(&archive),
                    output_path: Some(path_to_string(&output)),
                    password: Some("Strong#Pass123".to_string()),
                },
                None,
            )
            .expect("decompress encrypted");

            let restored = fs::read(&output).expect("read output");
            assert_eq!(restored, payload, "size={size}");
        }
    }

    #[test]
    fn encrypted_roundtrip_directory_include_root_variants() {
        let temp = tempfile::tempdir().expect("temp dir");
        let source_dir = temp.path().join("project_src");
        fs::create_dir_all(&source_dir).expect("create source dir");

        write_file(&source_dir.join("empty.txt"), b"");
        write_file(&source_dir.join("plain.txt"), b"hello encrypted world");
        write_file(&source_dir.join("config.json"), br#"{"k":1,"v":"x"}"#);
        write_file(
            &source_dir.join("nested/bin.dat"),
            &deterministic_bytes(131_072),
        );
        write_file(
            &source_dir.join("nested/unicode/中文-emoji.txt"),
            "你好, encryption ✓".as_bytes(),
        );
        write_file(
            &source_dir.join("nested/huge/chunk.bin"),
            &deterministic_bytes(ENC_CHUNK_SIZE * 2 + 77),
        );

        for include_root in [true, false] {
            let archive = temp.path().join(format!("dir_{include_root}.tar.zst.enc"));
            let out_dir = temp.path().join(format!("out_{include_root}"));

            compress_archive_sync(
                CompressRequest {
                    source_path: path_to_string(&source_dir),
                    output_path: Some(path_to_string(&archive)),
                    level: Some(6),
                    include_root_dir: Some(include_root),
                    password: Some("Dir#Secure987".to_string()),
                },
                None,
            )
            .expect("compress dir encrypted");

            decompress_archive_sync(
                DecompressRequest {
                    archive_path: path_to_string(&archive),
                    output_path: Some(path_to_string(&out_dir)),
                    password: Some("Dir#Secure987".to_string()),
                },
                None,
            )
            .expect("decompress dir encrypted");

            let actual_root = if include_root {
                out_dir.join("project_src")
            } else {
                out_dir.clone()
            };
            assert_dirs_equal(&source_dir, &actual_root);
        }
    }

    #[test]
    fn encrypted_archive_rejects_wrong_password() {
        let temp = tempfile::tempdir().expect("temp dir");
        let source = temp.path().join("secret.bin");
        let archive = temp.path().join("secret.zst.enc");
        let output = temp.path().join("secret.out");

        write_file(&source, &deterministic_bytes(8192));

        compress_archive_sync(
            CompressRequest {
                source_path: path_to_string(&source),
                output_path: Some(path_to_string(&archive)),
                level: Some(5),
                include_root_dir: Some(true),
                password: Some("CorrectPassword".to_string()),
            },
            None,
        )
        .expect("compress encrypted");

        let err = decompress_archive_sync(
            DecompressRequest {
                archive_path: path_to_string(&archive),
                output_path: Some(path_to_string(&output)),
                password: Some("WrongPassword".to_string()),
            },
            None,
        )
        .expect_err("wrong password must fail");

        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn plain_roundtrip_still_works_after_encryption_feature() {
        let temp = tempfile::tempdir().expect("temp dir");
        let source = temp.path().join("plain.bin");
        let archive = temp.path().join("plain.bin.zst");
        let output = temp.path().join("plain.out");

        let payload = deterministic_bytes(2 * 1024 * 1024 + 13);
        write_file(&source, &payload);

        compress_archive_sync(
            CompressRequest {
                source_path: path_to_string(&source),
                output_path: Some(path_to_string(&archive)),
                level: Some(9),
                include_root_dir: Some(true),
                password: None,
            },
            None,
        )
        .expect("compress plain");

        decompress_archive_sync(
            DecompressRequest {
                archive_path: path_to_string(&archive),
                output_path: Some(path_to_string(&output)),
                password: None,
            },
            None,
        )
        .expect("decompress plain");

        assert_eq!(fs::read(output).expect("read output"), payload);
    }

    #[test]
    fn benchmark_compression_returns_recommendation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let source_path = temp.path().join("blob.bin");
        write_file(&source_path, &deterministic_bytes(2 * 1024 * 1024));

        let report = benchmark_compression_sync(BenchmarkRequest {
            source_path: path_to_string(&source_path),
            min_level: Some(1),
            max_level: Some(4),
            iterations: Some(1),
            sample_size_mib: Some(16),
            threads: Some(1),
        })
        .expect("benchmark");

        assert_eq!(report.results.len(), 4);
        assert!((1..=4).contains(&report.recommended_level));
        assert!(report.sample_bytes > 0);
    }
}
