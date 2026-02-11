import { invoke } from '@tauri-apps/api/core';
import { open, save } from '@tauri-apps/plugin-dialog';
import './style.css';

interface OperationReport {
  operation: string;
  sourcePath: string;
  outputPath: string;
  sourceBytes: number;
  outputBytes: number;
  durationMs: number;
  throughputMiBs: number;
  compressionRatio: number | null;
}

interface BenchmarkReport {
  archivePath: string;
  mode: string;
  inMemory: boolean;
  warmup: number;
  iterations: number;
  compressedBytes: number;
  decompressedBytes: number;
  sampleMs: number[];
  throughputMiBsSamples: number[];
  meanMs: number;
  medianMs: number;
  p95Ms: number;
  minMs: number;
  maxMs: number;
  stddevMs: number;
  meanThroughputMiBs: number;
  bestThroughputMiBs: number;
  worstThroughputMiBs: number;
  note: string;
}

const compressSource = byId<HTMLInputElement>('compressSource');
const compressOutput = byId<HTMLInputElement>('compressOutput');
const compressLevel = byId<HTMLInputElement>('compressLevel');
const compressLevelLabel = byId<HTMLSpanElement>('compressLevelLabel');
const compressKindTag = byId<HTMLSpanElement>('compressKindTag');
const includeRootDir = byId<HTMLInputElement>('includeRootDir');
const compressResult = byId<HTMLElement>('compressResult');

const decompressSource = byId<HTMLInputElement>('decompressSource');
const decompressOutput = byId<HTMLInputElement>('decompressOutput');
const decompressResult = byId<HTMLElement>('decompressResult');

const benchmarkSource = byId<HTMLInputElement>('benchmarkSource');
const benchmarkIterations = byId<HTMLInputElement>('benchmarkIterations');
const benchmarkWarmup = byId<HTMLInputElement>('benchmarkWarmup');
const benchmarkInMemory = byId<HTMLInputElement>('benchmarkInMemory');
const benchmarkMode = byId<HTMLSelectElement>('benchmarkMode');
const benchmarkSummary = byId<HTMLElement>('benchmarkSummary');
const benchmarkBars = byId<HTMLElement>('benchmarkBars');

const statusEl = byId<HTMLElement>('status');

wireEvents();

function wireEvents() {
  compressLevel.addEventListener('input', () => {
    compressLevelLabel.textContent = compressLevel.value;
  });

  byId<HTMLButtonElement>('pickCompressFile').addEventListener('click', async () => {
    compressKindTag.textContent = '当前: 文件';
    const selected = await open({
      title: '选择待压缩文件',
      multiple: false,
      directory: false
    });
    if (typeof selected === 'string') {
      compressSource.value = selected;
    }
  });

  byId<HTMLButtonElement>('pickCompressDirectory').addEventListener('click', async () => {
    compressKindTag.textContent = '当前: 目录';
    const selected = await open({
      title: '选择待压缩目录',
      multiple: false,
      directory: true
    });
    if (typeof selected === 'string') {
      compressSource.value = selected;
    }
  });

  byId<HTMLButtonElement>('pickCompressOutput').addEventListener('click', async () => {
    const selected = await save({
      title: '压缩输出路径',
      filters: [{ name: 'Zstd Archive', extensions: ['zst'] }]
    });
    if (typeof selected === 'string') {
      compressOutput.value = selected;
    }
  });

  byId<HTMLButtonElement>('compressSubmit').addEventListener('click', async () => {
    if (!compressSource.value) {
      setStatus('请先选择压缩源路径。', 'error');
      return;
    }

    try {
      setBusy('正在压缩，请稍候...');
      const report = await invoke<OperationReport>('compress_archive', {
        request: {
          sourcePath: compressSource.value,
          outputPath: emptyToNull(compressOutput.value),
          level: toNumber(compressLevel.value, 8),
          includeRootDir: includeRootDir.checked
        }
      });
      compressResult.textContent = formatOperation(report);
      setStatus(`压缩完成: ${report.outputPath}`, 'success');
    } catch (error) {
      setStatus(normalizeError(error), 'error');
    }
  });

  byId<HTMLButtonElement>('pickDecompressSource').addEventListener('click', async () => {
    const selected = await open({
      title: '选择归档文件',
      multiple: false,
      directory: false,
      filters: [{ name: 'Zstd Archive', extensions: ['zst'] }]
    });
    if (typeof selected === 'string') {
      decompressSource.value = selected;
    }
  });

  byId<HTMLButtonElement>('pickDecompressOutput').addEventListener('click', async () => {
    const selected = await open({
      title: '选择解压输出目录',
      multiple: false,
      directory: true
    });
    if (typeof selected === 'string') {
      decompressOutput.value = selected;
    }
  });

  byId<HTMLButtonElement>('decompressSubmit').addEventListener('click', async () => {
    if (!decompressSource.value) {
      setStatus('请先选择归档文件。', 'error');
      return;
    }

    try {
      setBusy('正在解压，请稍候...');
      const report = await invoke<OperationReport>('decompress_archive', {
        request: {
          archivePath: decompressSource.value,
          outputPath: emptyToNull(decompressOutput.value)
        }
      });
      decompressResult.textContent = formatOperation(report);
      setStatus(`解压完成: ${report.outputPath}`, 'success');
    } catch (error) {
      setStatus(normalizeError(error), 'error');
    }
  });

  byId<HTMLButtonElement>('pickBenchmarkSource').addEventListener('click', async () => {
    const selected = await open({
      title: '选择用于性能测试的归档',
      multiple: false,
      directory: false,
      filters: [{ name: 'Zstd Archive', extensions: ['zst'] }]
    });
    if (typeof selected === 'string') {
      benchmarkSource.value = selected;
    }
  });

  byId<HTMLButtonElement>('benchmarkSubmit').addEventListener('click', async () => {
    if (!benchmarkSource.value) {
      setStatus('请先选择基准测试文件。', 'error');
      return;
    }

    try {
      setBusy('正在执行解压性能测试...');
      const report = await invoke<BenchmarkReport>('benchmark_decompression', {
        request: {
          archivePath: benchmarkSource.value,
          warmup: toNumber(benchmarkWarmup.value, 3),
          iterations: toNumber(benchmarkIterations.value, 12),
          mode: benchmarkMode.value,
          inMemory: benchmarkInMemory.checked
        }
      });
      renderBenchmark(report);
      setStatus('性能测试完成。', 'success');
    } catch (error) {
      setStatus(normalizeError(error), 'error');
    }
  });
}

function renderBenchmark(report: BenchmarkReport) {
  benchmarkSummary.innerHTML = `
    <div class="summary-grid">
      <div class="metric"><small>平均耗时</small><strong>${report.meanMs.toFixed(2)} ms</strong></div>
      <div class="metric"><small>中位耗时</small><strong>${report.medianMs.toFixed(2)} ms</strong></div>
      <div class="metric"><small>P95</small><strong>${report.p95Ms.toFixed(2)} ms</strong></div>
      <div class="metric"><small>平均吞吐</small><strong>${report.meanThroughputMiBs.toFixed(2)} MiB/s</strong></div>
      <div class="metric"><small>最佳吞吐</small><strong>${report.bestThroughputMiBs.toFixed(2)} MiB/s</strong></div>
      <div class="metric"><small>标准差</small><strong>${report.stddevMs.toFixed(2)} ms</strong></div>
    </div>
    <p class="hint" style="margin:10px 0 0;">${report.note}</p>
  `;

  const maxMs = Math.max(...report.sampleMs, 1);
  benchmarkBars.innerHTML = '';

  report.sampleMs.forEach((ms, index) => {
    const row = document.createElement('div');
    row.style.display = 'grid';
    row.style.gridTemplateColumns = '70px 1fr 68px';
    row.style.alignItems = 'center';
    row.style.gap = '8px';

    const label = document.createElement('small');
    label.textContent = `#${index + 1}`;
    label.style.color = '#5f6e7f';

    const bar = document.createElement('div');
    bar.className = 'bar';
    bar.style.width = `${Math.max((ms / maxMs) * 100, 4)}%`;

    const value = document.createElement('small');
    value.textContent = `${ms.toFixed(2)} ms`;
    value.style.color = '#315974';

    row.append(label, bar, value);
    benchmarkBars.append(row);
  });
}

function formatOperation(report: OperationReport): string {
  const ratio = report.compressionRatio === null ? '-' : `${report.compressionRatio.toFixed(2)}%`;
  return [
    `操作: ${report.operation}`,
    `源路径: ${report.sourcePath}`,
    `输出路径: ${report.outputPath}`,
    `源大小: ${formatBytes(report.sourceBytes)}`,
    `结果大小: ${formatBytes(report.outputBytes)}`,
    `压缩率: ${ratio}`,
    `耗时: ${report.durationMs.toFixed(2)} ms`,
    `吞吐: ${report.throughputMiBs.toFixed(2)} MiB/s`
  ].join('\n');
}

function setBusy(message: string) {
  statusEl.textContent = message;
  statusEl.className = 'status busy';
}

function setStatus(message: string, level: 'success' | 'error') {
  statusEl.textContent = message;
  statusEl.className = `status ${level}`;
}

function normalizeError(error: unknown): string {
  if (typeof error === 'string') {
    return error;
  }
  if (error && typeof error === 'object' && 'toString' in error) {
    return String(error);
  }
  return '发生未知错误。';
}

function byId<T extends HTMLElement>(id: string): T {
  const element = document.getElementById(id);
  if (!element) {
    throw new Error(`无法找到元素: ${id}`);
  }
  return element as T;
}

function toNumber(value: string, fallback: number): number {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) {
    return fallback;
  }
  return parsed;
}

function emptyToNull(value: string): string | null {
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : null;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ['KiB', 'MiB', 'GiB', 'TiB'];
  let value = bytes;
  let unitIndex = -1;
  do {
    value /= 1024;
    unitIndex += 1;
  } while (value >= 1024 && unitIndex < units.length - 1);

  return `${value.toFixed(2)} ${units[unitIndex]}`;
}
