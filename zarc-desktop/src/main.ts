import { invoke } from '@tauri-apps/api/core';
import { listen } from '@tauri-apps/api/event';
import { open, save } from '@tauri-apps/plugin-dialog';
import './style.css';

type ProgressKind = 'compress' | 'decompress';

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

interface ProgressPayload {
  operation: ProgressKind;
  processedBytes: number;
  totalBytes: number;
  percent: number;
  throughputMiBs: number;
  etaSeconds: number | null;
  done: boolean;
  error: string | null;
}

interface CompressionLevelReport {
  level: number;
  meanMs: number;
  meanThroughputMiBs: number;
  compressedBytes: number;
  ratioPercent: number;
  score: number;
}

interface CompressionBenchmarkReport {
  sourcePath: string;
  sampleBytes: number;
  minLevel: number;
  maxLevel: number;
  iterations: number;
  threads: number;
  recommendedLevel: number;
  results: CompressionLevelReport[];
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
const benchmarkKindTag = byId<HTMLSpanElement>('benchmarkKindTag');
const benchmarkMinLevel = byId<HTMLInputElement>('benchmarkMinLevel');
const benchmarkMaxLevel = byId<HTMLInputElement>('benchmarkMaxLevel');
const benchmarkIterations = byId<HTMLInputElement>('benchmarkIterations');
const benchmarkSampleSize = byId<HTMLInputElement>('benchmarkSampleSize');
const benchmarkSummary = byId<HTMLElement>('benchmarkSummary');
const benchmarkBars = byId<HTMLElement>('benchmarkBars');

const compressProgressBar = byId<HTMLElement>('compressProgressBar');
const compressProgressPercent = byId<HTMLElement>('compressProgressPercent');
const compressProgressText = byId<HTMLElement>('compressProgressText');
const compressProgressStats = byId<HTMLElement>('compressProgressStats');

const decompressProgressBar = byId<HTMLElement>('decompressProgressBar');
const decompressProgressPercent = byId<HTMLElement>('decompressProgressPercent');
const decompressProgressText = byId<HTMLElement>('decompressProgressText');
const decompressProgressStats = byId<HTMLElement>('decompressProgressStats');

const statusEl = byId<HTMLElement>('status');
const actionButtons = [
  byId<HTMLButtonElement>('compressSubmit'),
  byId<HTMLButtonElement>('decompressSubmit'),
  byId<HTMLButtonElement>('benchmarkSubmit')
];

void initProgressEvents();
wireEvents();

function wireEvents() {
  compressLevel.addEventListener('input', () => {
    compressLevelLabel.textContent = compressLevel.value;
  });

  byId<HTMLButtonElement>('pickCompressFile').addEventListener('click', async () => {
    compressKindTag.textContent = '当前: 文件';
    const selected = await open({ title: '选择待压缩文件', multiple: false, directory: false });
    if (typeof selected === 'string') {
      compressSource.value = selected;
    }
  });

  byId<HTMLButtonElement>('pickCompressDirectory').addEventListener('click', async () => {
    compressKindTag.textContent = '当前: 目录';
    const selected = await open({ title: '选择待压缩目录', multiple: false, directory: true });
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

    resetProgress('compress', '准备压缩...');

    await runTask('正在压缩，请稍候...', async () => {
      const report = await invoke<OperationReport>('compress_archive', {
        request: {
          sourcePath: compressSource.value,
          outputPath: emptyToNull(compressOutput.value),
          level: toInt(compressLevel.value, 8),
          includeRootDir: includeRootDir.checked
        }
      });
      compressResult.textContent = formatOperation(report);
      setStatus(`压缩完成: ${report.outputPath}`, 'success');
    });
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
    const selected = await open({ title: '选择解压输出目录', multiple: false, directory: true });
    if (typeof selected === 'string') {
      decompressOutput.value = selected;
    }
  });

  byId<HTMLButtonElement>('decompressSubmit').addEventListener('click', async () => {
    if (!decompressSource.value) {
      setStatus('请先选择归档文件。', 'error');
      return;
    }

    resetProgress('decompress', '准备解压...');

    await runTask('正在解压，请稍候...', async () => {
      const report = await invoke<OperationReport>('decompress_archive', {
        request: {
          archivePath: decompressSource.value,
          outputPath: emptyToNull(decompressOutput.value)
        }
      });
      decompressResult.textContent = formatOperation(report);
      setStatus(`解压完成: ${report.outputPath}`, 'success');
    });
  });

  byId<HTMLButtonElement>('pickBenchmarkFile').addEventListener('click', async () => {
    benchmarkKindTag.textContent = '当前: 文件';
    const selected = await open({ title: '选择快速测试文件', multiple: false, directory: false });
    if (typeof selected === 'string') {
      benchmarkSource.value = selected;
    }
  });

  byId<HTMLButtonElement>('pickBenchmarkDirectory').addEventListener('click', async () => {
    benchmarkKindTag.textContent = '当前: 目录';
    const selected = await open({ title: '选择快速测试目录', multiple: false, directory: true });
    if (typeof selected === 'string') {
      benchmarkSource.value = selected;
    }
  });

  byId<HTMLButtonElement>('benchmarkSubmit').addEventListener('click', async () => {
    if (!benchmarkSource.value) {
      setStatus('请先选择快速测试源路径。', 'error');
      return;
    }

    await runTask('正在快速评估压缩等级...', async () => {
      const report = await invoke<CompressionBenchmarkReport>('benchmark_compression', {
        request: {
          sourcePath: benchmarkSource.value,
          minLevel: toInt(benchmarkMinLevel.value, 1),
          maxLevel: toInt(benchmarkMaxLevel.value, 12),
          iterations: toInt(benchmarkIterations.value, 2),
          sampleSizeMiB: toInt(benchmarkSampleSize.value, 64)
        }
      });
      renderBenchmark(report);
      setStatus(`测试完成，推荐压缩等级 L${report.recommendedLevel}。`, 'success');
    });
  });
}

async function initProgressEvents() {
  await listen<ProgressPayload>('zarc://progress', (event) => {
    const payload = event.payload;
    updateProgress(payload.operation, payload);

    if (payload.done && payload.error) {
      setStatus(payload.error, 'error');
    }
  });
}

function updateProgress(kind: ProgressKind, payload: ProgressPayload) {
  const refs =
    kind === 'compress'
      ? {
          bar: compressProgressBar,
          percent: compressProgressPercent,
          text: compressProgressText,
          stats: compressProgressStats
        }
      : {
          bar: decompressProgressBar,
          percent: decompressProgressPercent,
          text: decompressProgressText,
          stats: decompressProgressStats
        };

  refs.bar.style.width = `${Math.max(0, Math.min(payload.percent, 100)).toFixed(2)}%`;
  refs.percent.textContent = `${payload.percent.toFixed(1)}%`;

  if (payload.done) {
    refs.text.textContent = payload.error ? '任务失败' : '任务完成';
  } else {
    refs.text.textContent = kind === 'compress' ? '压缩进行中' : '解压进行中';
  }

  const etaText = payload.etaSeconds === null ? '-' : `${formatSeconds(payload.etaSeconds)}`;
  refs.stats.textContent =
    `已处理 ${formatBytes(payload.processedBytes)} / ${formatBytes(payload.totalBytes)} • ` +
    `速度 ${payload.throughputMiBs.toFixed(2)} MiB/s • ETA ${etaText}`;
}

function resetProgress(kind: ProgressKind, text: string) {
  updateProgress(kind, {
    operation: kind,
    processedBytes: 0,
    totalBytes: 0,
    percent: 0,
    throughputMiBs: 0,
    etaSeconds: null,
    done: false,
    error: null
  });

  if (kind === 'compress') {
    compressProgressText.textContent = text;
    compressProgressStats.textContent = '-';
  } else {
    decompressProgressText.textContent = text;
    decompressProgressStats.textContent = '-';
  }
}

function renderBenchmark(report: CompressionBenchmarkReport) {
  if (report.results.length === 0) {
    benchmarkSummary.innerHTML = '<p class="hint">未获取到可用结果。</p>';
    benchmarkBars.innerHTML = '';
    return;
  }

  const bestThroughput = Math.max(...report.results.map((r) => r.meanThroughputMiBs));
  const bestRatio = Math.min(...report.results.map((r) => r.ratioPercent));

  benchmarkSummary.innerHTML = `
    <div class="summary-grid">
      <div class="metric"><small>推荐等级</small><strong>L${report.recommendedLevel}</strong></div>
      <div class="metric"><small>样本大小</small><strong>${formatBytes(report.sampleBytes)}</strong></div>
      <div class="metric"><small>线程数</small><strong>${report.threads}</strong></div>
      <div class="metric"><small>最高吞吐</small><strong>${bestThroughput.toFixed(2)} MiB/s</strong></div>
      <div class="metric"><small>最佳压缩率</small><strong>${bestRatio.toFixed(2)}%</strong></div>
      <div class="metric"><small>每等级轮数</small><strong>${report.iterations}</strong></div>
    </div>
    <p class="hint" style="margin:10px 0 0;">${report.note}</p>
  `;

  const maxScore = Math.max(...report.results.map((r) => r.score), 1e-6);
  benchmarkBars.innerHTML = '';

  for (const row of report.results) {
    const wrap = document.createElement('div');
    wrap.className = 'bench-row';

    const label = document.createElement('small');
    label.textContent = `L${row.level}`;
    label.className = 'bench-label';

    const meter = document.createElement('div');
    meter.className = 'bench-track';

    const fill = document.createElement('div');
    fill.className = `bench-fill${row.level === report.recommendedLevel ? ' recommended' : ''}`;
    fill.style.width = `${Math.max((row.score / maxScore) * 100, 6)}%`;
    meter.append(fill);

    const info = document.createElement('small');
    info.className = 'bench-value';
    info.textContent = `${row.meanThroughputMiBs.toFixed(1)} MiB/s • ${row.ratioPercent.toFixed(2)}%`;

    wrap.append(label, meter, info);
    benchmarkBars.append(wrap);
  }
}

async function runTask(statusText: string, task: () => Promise<void>) {
  setBusy(statusText);
  setActionsDisabled(true);
  try {
    await task();
  } catch (error) {
    setStatus(normalizeError(error), 'error');
  } finally {
    setActionsDisabled(false);
  }
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

function setActionsDisabled(disabled: boolean) {
  for (const button of actionButtons) {
    button.disabled = disabled;
  }
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

function toInt(value: string, fallback: number): number {
  const parsed = Number.parseInt(value, 10);
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

function formatSeconds(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) {
    return '-';
  }
  if (seconds < 60) {
    return `${seconds.toFixed(1)}s`;
  }
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  return `${mins}m ${secs.toFixed(0)}s`;
}
