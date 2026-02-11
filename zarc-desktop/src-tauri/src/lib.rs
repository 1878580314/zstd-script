use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Emitter};
use walkdir::WalkDir;

const IO_BUFFER_SIZE: usize = 8 * 1024 * 1024;
const MIB: f64 = 1024.0 * 1024.0;
const PROGRESS_EVENT: &str = "zarc://progress";
const PROGRESS_EMIT_INTERVAL: Duration = Duration::from_millis(120);

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct CompressRequest {
    source_path: String,
    output_path: Option<String>,
    level: Option<i32>,
    include_root_dir: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DecompressRequest {
    archive_path: String,
    output_path: Option<String>,
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

struct ProgressState {
    started: Instant,
    processed: AtomicU64,
    last_emit: Mutex<Instant>,
}

#[derive(Clone)]
struct ProgressReporter {
    app: AppHandle,
    operation: &'static str,
    total: u64,
    state: Arc<ProgressState>,
}

impl ProgressReporter {
    fn new(app: AppHandle, operation: &'static str, total: u64) -> Self {
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

        let _ = self.app.emit(PROGRESS_EVENT, payload);
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

#[tauri::command]
async fn compress_archive(
    app: AppHandle,
    request: CompressRequest,
) -> std::result::Result<OperationReport, String> {
    tauri::async_runtime::spawn_blocking(move || compress_archive_sync(request, app))
        .await
        .map_err(|err| format!("任务线程异常: {err}"))?
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn decompress_archive(
    app: AppHandle,
    request: DecompressRequest,
) -> std::result::Result<OperationReport, String> {
    tauri::async_runtime::spawn_blocking(move || decompress_archive_sync(request, app))
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

fn compress_archive_sync(request: CompressRequest, app: AppHandle) -> Result<OperationReport> {
    let source = PathBuf::from(request.source_path.trim());
    if !source.exists() {
        bail!("源路径不存在: {}", source.display());
    }

    let level = request.level.unwrap_or(8).clamp(1, 22);
    let include_root_dir = request.include_root_dir.unwrap_or(true);
    let source_bytes = count_source_bytes(&source)?;
    let output = resolve_compress_output(&source, request.output_path.as_deref())?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("无法创建输出目录: {}", parent.display()))?;
    }

    let reporter = ProgressReporter::new(app, "compress", source_bytes);
    reporter.begin();

    let started = Instant::now();
    let operation_result = if source.is_dir() {
        compress_directory(&source, &output, level, include_root_dir, &reporter)
    } else {
        compress_file(&source, &output, level, &reporter)
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

fn decompress_archive_sync(request: DecompressRequest, app: AppHandle) -> Result<OperationReport> {
    let archive = PathBuf::from(request.archive_path.trim());
    if !archive.exists() {
        bail!("归档文件不存在: {}", archive.display());
    }

    let archive_kind = detect_archive_kind(&archive)?;
    let source_bytes = fs::metadata(&archive)
        .with_context(|| format!("无法读取归档信息: {}", archive.display()))?
        .len();
    let output = resolve_decompress_output(&archive, archive_kind, request.output_path.as_deref())?;

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("无法创建输出目录: {}", parent.display()))?;
    }

    let reporter = ProgressReporter::new(app, "decompress", source_bytes);
    reporter.begin();

    let started = Instant::now();
    let operation_result = match archive_kind {
        ArchiveKind::TarZst => {
            fs::create_dir_all(&output)
                .with_context(|| format!("无法创建解压目录: {}", output.display()))?;
            decompress_tar_archive(&archive, &output, &reporter)?;
            Ok(count_source_bytes(&output)?)
        }
        ArchiveKind::Zst => decompress_single_file(&archive, &output, &reporter),
    };

    let output_bytes = match operation_result {
        Ok(value) => value,
        Err(err) => {
            reporter.fail(err.to_string());
            return Err(err);
        }
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
    reporter: &ProgressReporter,
) -> Result<()> {
    let input =
        File::open(source).with_context(|| format!("无法打开源文件: {}", source.display()))?;
    let output_file =
        File::create(output).with_context(|| format!("无法创建输出文件: {}", output.display()))?;

    let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let writer = BufWriter::with_capacity(IO_BUFFER_SIZE, output_file);
    let mut encoder = zstd::Encoder::new(writer, level).context("创建 zstd 编码器失败")?;

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

    let mut writer = encoder.finish().context("无法完成压缩输出")?;
    writer.flush().context("压缩结果刷盘失败")?;

    Ok(())
}

fn compress_directory(
    source: &Path,
    output: &Path,
    level: i32,
    include_root_dir: bool,
    reporter: &ProgressReporter,
) -> Result<()> {
    let output_file =
        File::create(output).with_context(|| format!("无法创建输出文件: {}", output.display()))?;
    let writer = BufWriter::with_capacity(IO_BUFFER_SIZE, output_file);
    let mut encoder = zstd::Encoder::new(writer, level).context("创建 zstd 编码器失败")?;

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
    let mut writer = encoder.finish().context("无法完成目录压缩输出")?;
    writer.flush().context("目录压缩结果刷盘失败")?;

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

fn decompress_tar_archive(
    archive_path: &Path,
    output_dir: &Path,
    reporter: &ProgressReporter,
) -> Result<()> {
    let input = File::open(archive_path)
        .with_context(|| format!("无法打开归档文件: {}", archive_path.display()))?;
    let reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let progress_reader = ProgressReader::new(reader, reporter.clone());
    let decoder = zstd::Decoder::new(progress_reader).context("创建 zstd 解码器失败")?;

    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(output_dir)
        .with_context(|| format!("解包归档失败: {}", output_dir.display()))?;

    Ok(())
}

fn decompress_single_file(
    archive_path: &Path,
    output_file: &Path,
    reporter: &ProgressReporter,
) -> Result<u64> {
    let input = File::open(archive_path)
        .with_context(|| format!("无法打开归档文件: {}", archive_path.display()))?;
    let reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let progress_reader = ProgressReader::new(reader, reporter.clone());
    let mut decoder = zstd::Decoder::new(progress_reader).context("创建 zstd 解码器失败")?;

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

fn detect_archive_kind(path: &Path) -> Result<ArchiveKind> {
    let name = path
        .file_name()
        .map(|v| v.to_string_lossy().to_lowercase())
        .unwrap_or_default();

    if name.ends_with(".tar.zst") {
        Ok(ArchiveKind::TarZst)
    } else if name.ends_with(".zst") {
        Ok(ArchiveKind::Zst)
    } else {
        bail!("不支持的文件类型，仅支持 .zst 和 .tar.zst")
    }
}

fn resolve_compress_output(source: &Path, output: Option<&str>) -> Result<PathBuf> {
    if let Some(path) = output {
        let candidate = PathBuf::from(path.trim());
        if candidate.exists() && candidate.is_dir() {
            let fallback_name = default_compress_file_name(source)?;
            return Ok(candidate.join(fallback_name));
        }
        return Ok(candidate);
    }

    let parent = source.parent().unwrap_or_else(|| Path::new("."));
    Ok(parent.join(default_compress_file_name(source)?))
}

fn default_compress_file_name(source: &Path) -> Result<String> {
    let source_name = source
        .file_name()
        .with_context(|| format!("无效路径: {}", source.display()))?
        .to_string_lossy();

    if source.is_dir() {
        Ok(format!("{source_name}.tar.zst"))
    } else {
        Ok(format!("{source_name}.zst"))
    }
}

fn resolve_decompress_output(
    archive: &Path,
    kind: ArchiveKind,
    output: Option<&str>,
) -> Result<PathBuf> {
    let default_name = default_decompress_name(archive, kind)?;

    match output {
        Some(path) => {
            let candidate = PathBuf::from(path.trim());
            match kind {
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

fn default_decompress_name(archive: &Path, kind: ArchiveKind) -> Result<String> {
    let file_name = archive
        .file_name()
        .with_context(|| format!("无效路径: {}", archive.display()))?
        .to_string_lossy();

    match kind {
        ArchiveKind::TarZst => {
            let base = file_name.trim_end_matches(".tar.zst");
            Ok(format!("{base}_extracted"))
        }
        ArchiveKind::Zst => {
            let base = file_name.trim_end_matches(".zst");
            Ok(base.to_string())
        }
    }
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
    use std::io::Write;

    #[test]
    fn benchmark_compression_returns_recommendation() {
        let temp = tempfile::tempdir().expect("temp dir");
        let source_path = temp.path().join("blob.bin");

        let payload = random_payload(2 * 1024 * 1024);
        let mut source = File::create(&source_path).expect("create source");
        source.write_all(payload.as_bytes()).expect("write payload");
        source.flush().expect("flush source");

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

    fn random_payload(size: usize) -> String {
        "zarc-benchmark-payload-".repeat(size / 23 + 1)[..size].to_string()
    }
}
