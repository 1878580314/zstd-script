#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod crypto;

use anyhow::{bail, Context, Result};
use crypto::{DecryptedReader, EncryptedWriter, MAGIC_HEADER};
use serde::Serialize;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tauri::Window;
use walkdir::WalkDir;

const IO_BUFFER_SIZE: usize = 1024 * 1024;
const PROGRESS_EMIT_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Clone, Serialize)]
struct ProgressEvent {
    step: String,
    percentage: f64,
    message: String,
}

#[derive(Serialize)]
struct OperationResult {
    output_path: String,
    input_bytes: u64,
    result_bytes: u64,
    duration_ms: u128,
    ratio: f64,
    message: String,
}

#[derive(Serialize)]
struct DecompressBenchmarkResult {
    source_path: String,
    archive_bytes: u64,
    decompressed_bytes: u64,
    warmup_runs: u32,
    measured_runs: u32,
    run_durations_ms: Vec<f64>,
    run_throughput_mb_s: Vec<f64>,
    avg_duration_ms: f64,
    median_duration_ms: f64,
    min_duration_ms: f64,
    max_duration_ms: f64,
    avg_throughput_mb_s: f64,
    median_throughput_mb_s: f64,
    best_throughput_mb_s: f64,
    message: String,
}

fn emit_progress(window: &Window, step: &str, percentage: f64, message: impl Into<String>) {
    let _ = window.emit(
        "progress",
        ProgressEvent {
            step: step.to_string(),
            percentage: percentage.clamp(0.0, 100.0),
            message: message.into(),
        },
    );
}

fn normalize_password(password: Option<String>) -> Option<String> {
    password.and_then(|pwd| {
        let trimmed = pwd.trim().to_string();
        if trimmed.is_empty() {
            None
        } else {
            Some(trimmed)
        }
    })
}

fn compression_ratio(result_bytes: u64, input_bytes: u64) -> f64 {
    if input_bytes == 0 {
        0.0
    } else {
        (result_bytes as f64 / input_bytes as f64) * 100.0
    }
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        0.0
    } else {
        values.iter().sum::<f64>() / values.len() as f64
    }
}

fn median(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }

    let mut sorted = values.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));

    let mid = sorted.len() / 2;
    if sorted.len() % 2 == 0 {
        (sorted[mid - 1] + sorted[mid]) / 2.0
    } else {
        sorted[mid]
    }
}

fn archive_is_tar(path: &Path) -> bool {
    let lower = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    lower.ends_with(".tar.zst") || lower.ends_with(".tar.zst.enc")
}

fn archive_is_encrypted(path: &Path) -> Result<bool> {
    let mut reader = BufReader::new(File::open(path).with_context(|| {
        format!(
            "failed to open archive for encryption detection: {}",
            path.display()
        )
    })?);

    let mut magic = [0_u8; MAGIC_HEADER.len()];
    let bytes_read = reader.read(&mut magic).with_context(|| {
        format!(
            "failed to read archive header while checking encryption: {}",
            path.display()
        )
    })?;

    Ok(bytes_read == MAGIC_HEADER.len() && &magic == MAGIC_HEADER)
}

fn decode_archive_to_sink_once(
    source: &Path,
    encrypted: bool,
    password: Option<&str>,
) -> Result<u64> {
    let source_file = File::open(source)
        .with_context(|| format!("failed to open archive {}", source.display()))?;
    let base_reader = BufReader::with_capacity(IO_BUFFER_SIZE, source_file);

    let stream = if encrypted {
        let pass = password
            .ok_or_else(|| anyhow::anyhow!("password is required for encrypted archives"))?;
        InputStream::Encrypted(
            DecryptedReader::new(base_reader, pass)
                .context("failed to initialize encrypted archive reader")?,
        )
    } else {
        InputStream::Plain(base_reader)
    };

    let mut decoder =
        zstd::stream::read::Decoder::new(stream).context("failed to initialize zstd decoder")?;

    io::copy(&mut decoder, &mut io::sink())
        .context("failed while decoding archive stream into sink")
}

fn source_size(path: &Path) -> Result<u64> {
    if path.is_file() {
        return Ok(fs::metadata(path)
            .with_context(|| format!("failed to read metadata for {}", path.display()))?
            .len());
    }

    if path.is_dir() {
        let mut size = 0_u64;
        for entry in WalkDir::new(path) {
            let entry =
                entry.with_context(|| format!("failed to walk directory {}", path.display()))?;
            if entry.file_type().is_file() {
                size = size.saturating_add(
                    entry
                        .metadata()
                        .with_context(|| {
                            format!(
                                "failed to read metadata for nested file {}",
                                entry.path().display()
                            )
                        })?
                        .len(),
                );
            }
        }
        return Ok(size);
    }

    bail!("unsupported source type: {}", path.display());
}

fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create output parent directory {}",
                    parent.display()
                )
            })?;
        }
    }
    Ok(())
}

struct ProgressPulse {
    total: u64,
    processed: u64,
    last_emitted: u64,
}

impl ProgressPulse {
    fn new(total: u64) -> Self {
        Self {
            total: total.max(1),
            processed: 0,
            last_emitted: 0,
        }
    }

    fn advance(&mut self, window: &Window, step: &str, delta: u64, message: &str) {
        self.processed = self.processed.saturating_add(delta);
        let should_emit = self.processed >= self.total
            || self.processed.saturating_sub(self.last_emitted) >= PROGRESS_EMIT_BYTES;
        if should_emit {
            self.last_emitted = self.processed;
            let pct = (self.processed as f64 / self.total as f64) * 100.0;
            emit_progress(window, step, pct, message);
        }
    }

    fn finish(&mut self, window: &Window, step: &str, message: &str) {
        self.processed = self.total;
        self.last_emitted = self.total;
        emit_progress(window, step, 100.0, message);
    }
}

struct CallbackProgressReader<R: Read> {
    inner: R,
    on_advance: Box<dyn FnMut(u64)>,
}

impl<R: Read> CallbackProgressReader<R> {
    fn new(inner: R, on_advance: Box<dyn FnMut(u64)>) -> Self {
        Self { inner, on_advance }
    }
}

impl<R: Read> Read for CallbackProgressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        if n > 0 {
            (self.on_advance)(n as u64);
        }
        Ok(n)
    }
}

enum InputStream<R: Read> {
    Plain(R),
    Encrypted(DecryptedReader<R>),
}

impl<R: Read> Read for InputStream<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(reader) => reader.read(buf),
            Self::Encrypted(reader) => reader.read(buf),
        }
    }
}

fn copy_with_progress<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    pulse: &mut ProgressPulse,
    window: &Window,
    step: &str,
    message: &str,
) -> Result<u64> {
    let mut buf = vec![0_u8; IO_BUFFER_SIZE];
    let mut written = 0_u64;

    loop {
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("failed to read source stream for step {step}"))?;
        if n == 0 {
            break;
        }

        writer
            .write_all(&buf[..n])
            .with_context(|| format!("failed to write destination stream for step {step}"))?;

        written = written.saturating_add(n as u64);
        pulse.advance(window, step, n as u64, message);
    }

    Ok(written)
}

fn append_directory_tar<W: Write>(
    source: &Path,
    writer: &mut W,
    pulse: &mut ProgressPulse,
    window: &Window,
) -> Result<()> {
    let source_parent = source.parent().unwrap_or_else(|| Path::new("."));
    let mut tar_builder = tar::Builder::new(writer);

    for entry in WalkDir::new(source).sort_by_file_name() {
        let entry = entry.with_context(|| format!("failed to walk {}", source.display()))?;
        let entry_path = entry.path();

        if entry.file_type().is_symlink() {
            continue;
        }

        let relative_path = entry_path.strip_prefix(source_parent).with_context(|| {
            format!(
                "failed to compute tar relative path: {}",
                entry_path.display()
            )
        })?;

        if relative_path.as_os_str().is_empty() {
            continue;
        }

        if entry.file_type().is_dir() {
            tar_builder
                .append_dir(relative_path, entry_path)
                .with_context(|| {
                    format!("failed to add directory to tar: {}", entry_path.display())
                })?;
            continue;
        }

        if entry.file_type().is_file() {
            tar_builder
                .append_path_with_name(entry_path, relative_path)
                .with_context(|| format!("failed to add file to tar: {}", entry_path.display()))?;

            let file_len = entry
                .metadata()
                .with_context(|| format!("failed to read metadata for {}", entry_path.display()))?
                .len();
            pulse.advance(
                window,
                "compress",
                file_len,
                "Packing and compressing directory...",
            );
        }
    }

    tar_builder
        .finish()
        .context("failed to finalize tar stream for directory compression")?;
    Ok(())
}

fn compress_pipeline<W: Write>(
    source: &Path,
    level: i32,
    total_source_bytes: u64,
    window: &Window,
    writer: W,
) -> Result<W> {
    let mut encoder = zstd::stream::write::Encoder::new(writer, level)
        .context("failed to initialize zstd encoder")?;

    let mut pulse = ProgressPulse::new(total_source_bytes);

    if source.is_file() {
        emit_progress(window, "compress", 0.0, "Compressing file...");
        let src_file = File::open(source)
            .with_context(|| format!("failed to open source file {}", source.display()))?;
        let mut src_reader = BufReader::new(src_file);
        copy_with_progress(
            &mut src_reader,
            &mut encoder,
            &mut pulse,
            window,
            "compress",
            "Compressing file...",
        )?;
    } else {
        emit_progress(
            window,
            "compress",
            0.0,
            "Packing and compressing directory...",
        );
        append_directory_tar(source, &mut encoder, &mut pulse, window)?;
    }

    pulse.finish(window, "compress", "Finalizing archive...");

    encoder
        .finish()
        .context("failed to finish zstd compressed output")
}

fn compress_internal(
    window: &Window,
    source: PathBuf,
    output: PathBuf,
    password: Option<String>,
    level: i32,
) -> Result<OperationResult> {
    if !source.exists() {
        bail!("source path does not exist: {}", source.display());
    }

    let level = level.clamp(1, 22);
    let input_bytes = source_size(&source)?;

    ensure_parent(&output)?;
    emit_progress(window, "init", 0.0, "Preparing compression job...");

    let started = Instant::now();
    let file = File::create(&output)
        .with_context(|| format!("failed to create output archive {}", output.display()))?;
    let buffered = BufWriter::new(file);

    match password {
        Some(pass) => {
            let encrypted = EncryptedWriter::new(buffered, &pass)
                .context("failed to initialize encrypted output stream")?;
            let encrypted = compress_pipeline(&source, level, input_bytes, window, encrypted)?;
            let mut plain_writer = encrypted
                .finish()
                .context("failed to finalize encrypted output stream")?;
            plain_writer
                .flush()
                .context("failed to flush output file after encryption")?;
        }
        None => {
            let mut writer = compress_pipeline(&source, level, input_bytes, window, buffered)?;
            writer
                .flush()
                .context("failed to flush compressed output file")?;
        }
    }

    emit_progress(window, "done", 100.0, "Compression completed.");

    let result_bytes = fs::metadata(&output)
        .with_context(|| format!("failed to read output metadata {}", output.display()))?
        .len();

    Ok(OperationResult {
        output_path: output.display().to_string(),
        input_bytes,
        result_bytes,
        duration_ms: started.elapsed().as_millis(),
        ratio: compression_ratio(result_bytes, input_bytes),
        message: "Compression completed successfully".to_string(),
    })
}

fn decompress_internal(
    window: &Window,
    source: PathBuf,
    output: PathBuf,
    password: Option<String>,
) -> Result<OperationResult> {
    if !source.is_file() {
        bail!(
            "source archive is missing or not a file: {}",
            source.display()
        );
    }

    let archive_size = fs::metadata(&source)
        .with_context(|| format!("failed to read source metadata {}", source.display()))?
        .len();
    let encrypted = archive_is_encrypted(&source)?;
    let is_tar = archive_is_tar(&source);

    let pass = if encrypted {
        password.ok_or_else(|| anyhow::anyhow!("password is required for encrypted archives"))?
    } else {
        String::new()
    };

    if is_tar {
        fs::create_dir_all(&output)
            .with_context(|| format!("failed to create output directory {}", output.display()))?;
    } else {
        ensure_parent(&output)?;
    }

    emit_progress(window, "init", 0.0, "Preparing extraction job...");

    let started = Instant::now();
    let source_file = File::open(&source)
        .with_context(|| format!("failed to open source archive {}", source.display()))?;

    let window_for_progress = window.clone();
    let mut pulse = ProgressPulse::new(archive_size);
    let callback = move |delta: u64| {
        pulse.advance(
            &window_for_progress,
            "decompress",
            delta,
            "Reading archive stream...",
        );
    };

    let base_reader = CallbackProgressReader::new(BufReader::new(source_file), Box::new(callback));
    let stream = if encrypted {
        InputStream::Encrypted(
            DecryptedReader::new(base_reader, &pass)
                .context("failed to initialize encrypted archive reader")?,
        )
    } else {
        InputStream::Plain(base_reader)
    };

    let mut decoder = zstd::stream::read::Decoder::new(stream)
        .context("failed to initialize zstd decoder for extraction")?;

    let result_bytes = if is_tar {
        let mut archive = tar::Archive::new(&mut decoder);
        archive
            .unpack(&output)
            .with_context(|| format!("failed to unpack tar archive into {}", output.display()))?;
        source_size(&output)?
    } else {
        let output_file = File::create(&output)
            .with_context(|| format!("failed to create extracted file {}", output.display()))?;
        let mut out_writer = BufWriter::new(output_file);
        let bytes = io::copy(&mut decoder, &mut out_writer)
            .context("failed while decompressing archive stream")?;
        out_writer
            .flush()
            .with_context(|| format!("failed to flush extracted file {}", output.display()))?;
        bytes
    };

    emit_progress(window, "done", 100.0, "Extraction completed.");

    Ok(OperationResult {
        output_path: output.display().to_string(),
        input_bytes: archive_size,
        result_bytes,
        duration_ms: started.elapsed().as_millis(),
        ratio: compression_ratio(result_bytes, archive_size),
        message: "Decompression completed successfully".to_string(),
    })
}

fn verify_internal(
    window: &Window,
    source: PathBuf,
    password: Option<String>,
) -> Result<OperationResult> {
    if !source.is_file() {
        bail!("archive does not exist: {}", source.display());
    }

    let archive_size = fs::metadata(&source)
        .with_context(|| format!("failed to read metadata for {}", source.display()))?
        .len();
    let encrypted = archive_is_encrypted(&source)?;
    let is_tar = archive_is_tar(&source);

    let pass = if encrypted {
        password.ok_or_else(|| anyhow::anyhow!("password is required for encrypted archives"))?
    } else {
        String::new()
    };

    emit_progress(window, "init", 0.0, "Preparing archive verification...");
    let started = Instant::now();

    let source_file = File::open(&source)
        .with_context(|| format!("failed to open archive {}", source.display()))?;

    let window_for_progress = window.clone();
    let mut pulse = ProgressPulse::new(archive_size);
    let callback = move |delta: u64| {
        pulse.advance(
            &window_for_progress,
            "verify",
            delta,
            "Checking archive integrity...",
        );
    };

    let base_reader = CallbackProgressReader::new(BufReader::new(source_file), Box::new(callback));
    let stream = if encrypted {
        InputStream::Encrypted(
            DecryptedReader::new(base_reader, &pass)
                .context("failed to initialize encrypted archive reader")?,
        )
    } else {
        InputStream::Plain(base_reader)
    };

    let mut decoder = zstd::stream::read::Decoder::new(stream)
        .context("failed to initialize zstd decoder for verification")?;

    if is_tar {
        let mut archive = tar::Archive::new(&mut decoder);
        for entry in archive
            .entries()
            .context("failed to iterate tar entries during verification")?
        {
            let mut item = entry.context("failed to read tar entry during verification")?;
            io::copy(&mut item, &mut io::sink())
                .context("failed while validating tar entry stream")?;
        }
    } else {
        io::copy(&mut decoder, &mut io::sink())
            .context("failed while reading archive stream for verification")?;
    }

    emit_progress(window, "done", 100.0, "Archive integrity verified.");

    Ok(OperationResult {
        output_path: source.display().to_string(),
        input_bytes: archive_size,
        result_bytes: archive_size,
        duration_ms: started.elapsed().as_millis(),
        ratio: 100.0,
        message: "Archive verification passed".to_string(),
    })
}

fn benchmark_decompress_internal(
    window: &Window,
    source: PathBuf,
    password: Option<String>,
    warmup_runs: u32,
    measured_runs: u32,
) -> Result<DecompressBenchmarkResult> {
    if !source.is_file() {
        bail!("archive does not exist: {}", source.display());
    }

    let archive_size = fs::metadata(&source)
        .with_context(|| format!("failed to read metadata for {}", source.display()))?
        .len();
    let encrypted = archive_is_encrypted(&source)?;
    let pass = if encrypted {
        Some(
            password
                .ok_or_else(|| anyhow::anyhow!("password is required for encrypted archives"))?,
        )
    } else {
        None
    };

    let warmup_runs = warmup_runs.min(10);
    let measured_runs = measured_runs.clamp(1, 20);
    let total_runs = warmup_runs + measured_runs;

    emit_progress(
        window,
        "benchmark",
        0.0,
        "Preparing decompression benchmark...",
    );

    let mut decompressed_bytes: Option<u64> = None;
    let mut run_durations_ms = Vec::with_capacity(measured_runs as usize);
    let mut run_throughput_mb_s = Vec::with_capacity(measured_runs as usize);

    for idx in 0..total_runs {
        let is_warmup = idx < warmup_runs;
        let run_index = idx + 1;
        let stage = if is_warmup { "Warmup" } else { "Measured" };
        emit_progress(
            window,
            "benchmark",
            (idx as f64 / total_runs as f64) * 100.0,
            format!("{stage} run {run_index}/{total_runs} in progress..."),
        );

        let start = Instant::now();
        let decoded = decode_archive_to_sink_once(&source, encrypted, pass.as_deref())?;
        let elapsed = start.elapsed();

        if let Some(previous) = decompressed_bytes {
            if previous != decoded {
                bail!("decoded size changed between runs, benchmark aborted for consistency");
            }
        } else {
            decompressed_bytes = Some(decoded);
        }

        if !is_warmup {
            let elapsed_ms = elapsed.as_secs_f64() * 1000.0;
            let elapsed_s = elapsed.as_secs_f64().max(1e-9);
            let throughput_mb_s = (decoded as f64 / (1024.0 * 1024.0)) / elapsed_s;
            run_durations_ms.push(elapsed_ms);
            run_throughput_mb_s.push(throughput_mb_s);
        }
    }

    emit_progress(window, "done", 100.0, "Decompression benchmark completed.");

    let avg_duration_ms = mean(&run_durations_ms);
    let median_duration_ms = median(&run_durations_ms);
    let min_duration_ms = run_durations_ms
        .iter()
        .copied()
        .reduce(f64::min)
        .unwrap_or(0.0);
    let max_duration_ms = run_durations_ms
        .iter()
        .copied()
        .reduce(f64::max)
        .unwrap_or(0.0);
    let avg_throughput_mb_s = mean(&run_throughput_mb_s);
    let median_throughput_mb_s = median(&run_throughput_mb_s);
    let best_throughput_mb_s = run_throughput_mb_s
        .iter()
        .copied()
        .reduce(f64::max)
        .unwrap_or(0.0);

    Ok(DecompressBenchmarkResult {
        source_path: source.display().to_string(),
        archive_bytes: archive_size,
        decompressed_bytes: decompressed_bytes.unwrap_or(0),
        warmup_runs,
        measured_runs,
        run_durations_ms,
        run_throughput_mb_s,
        avg_duration_ms,
        median_duration_ms,
        min_duration_ms,
        max_duration_ms,
        avg_throughput_mb_s,
        median_throughput_mb_s,
        best_throughput_mb_s,
        message: "Benchmark finished. Results are measured without disk write extraction overhead."
            .to_string(),
    })
}

#[tauri::command]
fn compress(
    window: Window,
    source: String,
    output: String,
    password: Option<String>,
    level: Option<i32>,
) -> Result<OperationResult, String> {
    compress_internal(
        &window,
        PathBuf::from(source),
        PathBuf::from(output),
        normalize_password(password),
        level.unwrap_or(3),
    )
    .map_err(|err| err.to_string())
}

#[tauri::command]
fn decompress(
    window: Window,
    source: String,
    output: String,
    password: Option<String>,
) -> Result<OperationResult, String> {
    decompress_internal(
        &window,
        PathBuf::from(source),
        PathBuf::from(output),
        normalize_password(password),
    )
    .map_err(|err| err.to_string())
}

#[tauri::command]
fn verify(
    window: Window,
    source: String,
    password: Option<String>,
) -> Result<OperationResult, String> {
    verify_internal(&window, PathBuf::from(source), normalize_password(password))
        .map_err(|err| err.to_string())
}

#[tauri::command]
fn benchmark_decompress(
    window: Window,
    source: String,
    password: Option<String>,
    warmup_runs: Option<u32>,
    measured_runs: Option<u32>,
) -> Result<DecompressBenchmarkResult, String> {
    benchmark_decompress_internal(
        &window,
        PathBuf::from(source),
        normalize_password(password),
        warmup_runs.unwrap_or(1),
        measured_runs.unwrap_or(3),
    )
    .map_err(|err| err.to_string())
}

fn main() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            compress,
            decompress,
            verify,
            benchmark_decompress
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
