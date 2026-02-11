use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

const IO_BUFFER_SIZE: usize = 8 * 1024 * 1024;
const MIB: f64 = 1024.0 * 1024.0;

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
    archive_path: String,
    iterations: Option<u32>,
    warmup: Option<u32>,
    mode: Option<String>,
    in_memory: Option<bool>,
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

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct BenchmarkReport {
    archive_path: String,
    mode: String,
    in_memory: bool,
    warmup: u32,
    iterations: u32,
    compressed_bytes: u64,
    decompressed_bytes: u64,
    sample_ms: Vec<f64>,
    throughput_mi_bs_samples: Vec<f64>,
    mean_ms: f64,
    median_ms: f64,
    p95_ms: f64,
    min_ms: f64,
    max_ms: f64,
    stddev_ms: f64,
    mean_throughput_mi_bs: f64,
    best_throughput_mi_bs: f64,
    worst_throughput_mi_bs: f64,
    note: String,
}

#[derive(Debug, Copy, Clone)]
enum ArchiveKind {
    TarZst,
    Zst,
}

#[derive(Debug, Copy, Clone)]
enum BenchmarkMode {
    DecodeOnly,
    ExtractArchive,
}

impl BenchmarkMode {
    fn parse(mode: Option<&str>) -> Result<Self> {
        match mode.unwrap_or("decodeOnly") {
            "decodeOnly" => Ok(Self::DecodeOnly),
            "extractArchive" => Ok(Self::ExtractArchive),
            other => bail!("不支持的 benchmark 模式: {other}"),
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::DecodeOnly => "decodeOnly",
            Self::ExtractArchive => "extractArchive",
        }
    }
}

#[tauri::command]
async fn compress_archive(
    request: CompressRequest,
) -> std::result::Result<OperationReport, String> {
    tauri::async_runtime::spawn_blocking(move || compress_archive_sync(request))
        .await
        .map_err(|err| format!("任务线程异常: {err}"))?
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn decompress_archive(
    request: DecompressRequest,
) -> std::result::Result<OperationReport, String> {
    tauri::async_runtime::spawn_blocking(move || decompress_archive_sync(request))
        .await
        .map_err(|err| format!("任务线程异常: {err}"))?
        .map_err(|err| err.to_string())
}

#[tauri::command]
async fn benchmark_decompression(
    request: BenchmarkRequest,
) -> std::result::Result<BenchmarkReport, String> {
    tauri::async_runtime::spawn_blocking(move || benchmark_decompression_sync(request))
        .await
        .map_err(|err| format!("任务线程异常: {err}"))?
        .map_err(|err| err.to_string())
}

fn compress_archive_sync(request: CompressRequest) -> Result<OperationReport> {
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

    let started = Instant::now();

    if source.is_dir() {
        compress_directory(&source, &output, level, include_root_dir)?;
    } else {
        compress_file(&source, &output, level)?;
    }

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

fn decompress_archive_sync(request: DecompressRequest) -> Result<OperationReport> {
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

    let started = Instant::now();

    let output_bytes = match archive_kind {
        ArchiveKind::TarZst => {
            fs::create_dir_all(&output)
                .with_context(|| format!("无法创建解压目录: {}", output.display()))?;
            decompress_tar_archive(&archive, &output)?;
            count_source_bytes(&output)?
        }
        ArchiveKind::Zst => decompress_single_file(&archive, &output)?,
    };

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

fn benchmark_decompression_sync(request: BenchmarkRequest) -> Result<BenchmarkReport> {
    let archive = PathBuf::from(request.archive_path.trim());
    if !archive.exists() {
        bail!("归档文件不存在: {}", archive.display());
    }

    let archive_kind = detect_archive_kind(&archive)?;
    let mode = BenchmarkMode::parse(request.mode.as_deref())?;
    if matches!(mode, BenchmarkMode::ExtractArchive) && !matches!(archive_kind, ArchiveKind::TarZst)
    {
        bail!("extractArchive 模式仅支持 .tar.zst 文件");
    }

    let iterations = request.iterations.unwrap_or(12).clamp(3, 200);
    let warmup = request.warmup.unwrap_or(3).clamp(0, 100);
    let in_memory = request.in_memory.unwrap_or(true);

    let compressed_bytes = fs::metadata(&archive)
        .with_context(|| format!("无法读取归档信息: {}", archive.display()))?
        .len();

    let compressed_data = if in_memory {
        Some(
            fs::read(&archive)
                .with_context(|| format!("无法读取归档到内存: {}", archive.display()))?,
        )
    } else {
        None
    };

    let run_once = || -> Result<u64> {
        match mode {
            BenchmarkMode::DecodeOnly => {
                if let Some(data) = compressed_data.as_deref() {
                    decode_to_sink_from_bytes(data)
                } else {
                    decode_to_sink_from_file(&archive)
                }
            }
            BenchmarkMode::ExtractArchive => {
                if let Some(data) = compressed_data.as_deref() {
                    extract_archive_from_bytes(data)
                } else {
                    extract_archive_from_file(&archive)
                }
            }
        }
    };

    let mut decompressed_bytes = 0_u64;

    for _ in 0..warmup {
        decompressed_bytes = run_once()?;
    }

    let mut sample_ms = Vec::with_capacity(iterations as usize);
    let mut throughput_samples = Vec::with_capacity(iterations as usize);

    for _ in 0..iterations {
        let start = Instant::now();
        let bytes = run_once()?;
        let elapsed = start.elapsed().as_secs_f64();

        if decompressed_bytes == 0 {
            decompressed_bytes = bytes;
        }
        if bytes != decompressed_bytes {
            bail!(
                "基准测试中解压字节数不一致: 期望 {}, 实际 {}",
                decompressed_bytes,
                bytes
            );
        }

        sample_ms.push(elapsed * 1000.0);
        throughput_samples.push(throughput(bytes, elapsed));
    }

    let sorted_ms = sorted_clone(&sample_ms);
    let sorted_tp = sorted_clone(&throughput_samples);

    let mean_ms = mean(&sample_ms);
    let mean_tp = mean(&throughput_samples);

    let note = if in_memory {
        "结果已尽量剔除磁盘 I/O 抖动，更适合压缩算法/参数对比。"
    } else {
        "结果包含存储介质影响，更接近端到端真实场景。"
    }
    .to_string();

    let stddev_ms = stddev(&sample_ms, mean_ms);

    Ok(BenchmarkReport {
        archive_path: path_to_string(&archive),
        mode: mode.as_str().to_string(),
        in_memory,
        warmup,
        iterations,
        compressed_bytes,
        decompressed_bytes,
        sample_ms,
        throughput_mi_bs_samples: throughput_samples,
        mean_ms,
        median_ms: percentile_sorted(&sorted_ms, 0.50),
        p95_ms: percentile_sorted(&sorted_ms, 0.95),
        min_ms: *sorted_ms.first().unwrap_or(&0.0),
        max_ms: *sorted_ms.last().unwrap_or(&0.0),
        stddev_ms,
        mean_throughput_mi_bs: mean_tp,
        best_throughput_mi_bs: *sorted_tp.last().unwrap_or(&0.0),
        worst_throughput_mi_bs: *sorted_tp.first().unwrap_or(&0.0),
        note,
    })
}

fn compress_file(source: &Path, output: &Path, level: i32) -> Result<()> {
    let input =
        File::open(source).with_context(|| format!("无法打开源文件: {}", source.display()))?;
    let output_file =
        File::create(output).with_context(|| format!("无法创建输出文件: {}", output.display()))?;

    let mut reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let writer = BufWriter::with_capacity(IO_BUFFER_SIZE, output_file);
    let mut encoder = zstd::Encoder::new(writer, level)?;

    let threads = num_cpus::get().max(1) as u32;
    encoder
        .multithread(threads)
        .context("无法开启 zstd 多线程压缩")?;

    io::copy(&mut reader, &mut encoder).context("压缩过程中写入失败")?;
    let mut writer = encoder.finish().context("无法完成压缩输出")?;
    writer.flush().context("压缩结果刷盘失败")?;

    Ok(())
}

fn compress_directory(
    source: &Path,
    output: &Path,
    level: i32,
    include_root_dir: bool,
) -> Result<()> {
    let output_file =
        File::create(output).with_context(|| format!("无法创建输出文件: {}", output.display()))?;
    let writer = BufWriter::with_capacity(IO_BUFFER_SIZE, output_file);
    let mut encoder = zstd::Encoder::new(writer, level)?;

    let threads = num_cpus::get().max(1) as u32;
    encoder
        .multithread(threads)
        .context("无法开启 zstd 多线程压缩")?;

    let mut tar_builder = tar::Builder::new(encoder);

    if include_root_dir {
        let root_name = source
            .file_name()
            .with_context(|| format!("目录名称无效: {}", source.display()))?;
        tar_builder
            .append_dir_all(root_name, source)
            .with_context(|| format!("写入目录归档失败: {}", source.display()))?;
    } else {
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

            if entry.file_type().is_dir() {
                tar_builder
                    .append_dir(rel, path)
                    .with_context(|| format!("写入目录失败: {}", path.display()))?;
            } else if entry.file_type().is_file() {
                tar_builder
                    .append_path_with_name(path, rel)
                    .with_context(|| format!("写入文件失败: {}", path.display()))?;
            }
        }
    }

    tar_builder.finish().context("tar 归档收尾失败")?;
    let encoder = tar_builder.into_inner().context("无法获取压缩编码器")?;
    let mut writer = encoder.finish().context("无法完成目录压缩输出")?;
    writer.flush().context("目录压缩结果刷盘失败")?;

    Ok(())
}

fn decompress_tar_archive(archive_path: &Path, output_dir: &Path) -> Result<()> {
    let input = File::open(archive_path)
        .with_context(|| format!("无法打开归档文件: {}", archive_path.display()))?;
    let reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let decoder = zstd::Decoder::new(reader).context("创建 zstd 解码器失败")?;

    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(output_dir)
        .with_context(|| format!("解包归档失败: {}", output_dir.display()))?;

    Ok(())
}

fn decompress_single_file(archive_path: &Path, output_file: &Path) -> Result<u64> {
    let input = File::open(archive_path)
        .with_context(|| format!("无法打开归档文件: {}", archive_path.display()))?;
    let reader = BufReader::with_capacity(IO_BUFFER_SIZE, input);
    let mut decoder = zstd::Decoder::new(reader).context("创建 zstd 解码器失败")?;

    let output = File::create(output_file)
        .with_context(|| format!("无法创建输出文件: {}", output_file.display()))?;
    let mut writer = BufWriter::with_capacity(IO_BUFFER_SIZE, output);

    let bytes = io::copy(&mut decoder, &mut writer).context("写入解压输出失败")?;
    writer.flush().context("解压结果刷盘失败")?;

    Ok(bytes)
}

fn decode_to_sink_from_file(path: &Path) -> Result<u64> {
    let file = File::open(path).with_context(|| format!("无法打开文件: {}", path.display()))?;
    let reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);
    decode_to_sink(reader)
}

fn decode_to_sink_from_bytes(data: &[u8]) -> Result<u64> {
    let cursor = Cursor::new(data);
    decode_to_sink(cursor)
}

fn decode_to_sink<R: Read>(source: R) -> Result<u64> {
    let mut decoder = zstd::Decoder::new(source).context("创建 zstd 解码器失败")?;
    let bytes = io::copy(&mut decoder, &mut io::sink()).context("解码到 sink 失败")?;
    Ok(bytes)
}

fn extract_archive_from_file(path: &Path) -> Result<u64> {
    let file = File::open(path).with_context(|| format!("无法打开文件: {}", path.display()))?;
    let reader = BufReader::with_capacity(IO_BUFFER_SIZE, file);
    extract_archive(reader)
}

fn extract_archive_from_bytes(data: &[u8]) -> Result<u64> {
    let cursor = Cursor::new(data);
    extract_archive(cursor)
}

fn extract_archive<R: Read>(source: R) -> Result<u64> {
    let tempdir = tempfile::tempdir().context("创建临时目录失败")?;
    let decoder = zstd::Decoder::new(source).context("创建 zstd 解码器失败")?;
    let mut archive = tar::Archive::new(decoder);

    archive
        .unpack(tempdir.path())
        .context("解包归档失败，可能并非 tar.zst")?;

    count_source_bytes(tempdir.path())
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

fn path_to_string(path: &Path) -> String {
    path.to_string_lossy().to_string()
}

fn sorted_clone(values: &[f64]) -> Vec<f64> {
    let mut cloned = values.to_vec();
    cloned.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    cloned
}

fn percentile_sorted(sorted: &[f64], percentile: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }

    let rank = ((sorted.len() as f64 - 1.0) * percentile.clamp(0.0, 1.0)).round() as usize;
    sorted[rank]
}

fn mean(values: &[f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.iter().sum::<f64>() / values.len() as f64
}

fn stddev(values: &[f64], mean: f64) -> f64 {
    if values.len() < 2 {
        return 0.0;
    }

    let variance = values
        .iter()
        .map(|v| {
            let delta = *v - mean;
            delta * delta
        })
        .sum::<f64>()
        / values.len() as f64;

    variance.sqrt()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            compress_archive,
            decompress_archive,
            benchmark_decompression
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn benchmark_decode_only_returns_expected_shape() {
        let temp = tempfile::tempdir().expect("temp dir");
        let source_path = temp.path().join("blob.bin");
        let archive_path = temp.path().join("blob.bin.zst");

        let payload = random_payload(2 * 1024 * 1024);
        let mut source = File::create(&source_path).expect("create source");
        source.write_all(payload.as_bytes()).expect("write payload");
        source.flush().expect("flush source");

        let input = File::open(&source_path).expect("open source");
        let output = File::create(&archive_path).expect("create archive");
        let mut encoder = zstd::Encoder::new(output, 6).expect("encoder");
        io::copy(&mut BufReader::new(input), &mut encoder).expect("compress");
        encoder.finish().expect("finish");

        let report = benchmark_decompression_sync(BenchmarkRequest {
            archive_path: path_to_string(&archive_path),
            iterations: Some(5),
            warmup: Some(1),
            mode: Some("decodeOnly".to_string()),
            in_memory: Some(true),
        })
        .expect("benchmark");

        assert_eq!(report.iterations, 5);
        assert_eq!(report.warmup, 1);
        assert_eq!(report.sample_ms.len(), 5);
        assert_eq!(report.throughput_mi_bs_samples.len(), 5);
        assert!(report.decompressed_bytes > 0);
        assert!(report.mean_ms >= 0.0);
    }

    fn random_payload(size: usize) -> String {
        "zarc-benchmark-payload-".repeat(size / 23 + 1)[..size].to_string()
    }
}
