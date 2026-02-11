import { useEffect, useMemo, useState } from "react";
import { invoke } from "@tauri-apps/api/tauri";
import { listen } from "@tauri-apps/api/event";
import { open, save } from "@tauri-apps/api/dialog";
import {
  Archive,
  CheckCircle2,
  FileArchive,
  FileDown,
  FileSearch,
  FolderOpen,
  Gauge,
  KeyRound,
  Loader2,
  Lock,
  Play,
  Sparkles,
  Upload,
} from "lucide-react";

type Mode = "compress" | "decompress" | "verify" | "benchmark";
type SourceKind = "file" | "directory" | null;

type ProgressPayload = {
  step: string;
  percentage: number;
  message: string;
};

type OperationResult = {
  output_path: string;
  input_bytes: number;
  result_bytes: number;
  duration_ms: number;
  ratio: number;
  message: string;
};

type BenchmarkResult = {
  source_path: string;
  archive_bytes: number;
  decompressed_bytes: number;
  warmup_runs: number;
  measured_runs: number;
  run_durations_ms: number[];
  run_throughput_mb_s: number[];
  avg_duration_ms: number;
  median_duration_ms: number;
  min_duration_ms: number;
  max_duration_ms: number;
  avg_throughput_mb_s: number;
  median_throughput_mb_s: number;
  best_throughput_mb_s: number;
  message: string;
};

const MODE_META: Record<Mode, { title: string; subtitle: string }> = {
  compress: {
    title: "压缩归档",
    subtitle: "Rust 流式压缩 + 可选 AES-256-GCM 加密",
  },
  decompress: {
    title: "解压还原",
    subtitle: "自动识别加密归档，支持文件与目录归档",
  },
  verify: {
    title: "完整性校验",
    subtitle: "不落盘提取，快速验证归档可读性",
  },
  benchmark: {
    title: "性能测试",
    subtitle: "准确测量解压缩吞吐，排除落盘写入干扰",
  },
};

function isTarArchive(path: string): boolean {
  const lower = path.toLowerCase();
  return lower.endsWith(".tar.zst") || lower.endsWith(".tar.zst.enc");
}

function stripArchiveSuffix(path: string): string {
  return path
    .replace(/\.enc$/i, "")
    .replace(/\.tar\.zst$/i, "")
    .replace(/\.zst$/i, "");
}

function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[idx]}`;
}

export default function App() {
  const [mode, setMode] = useState<Mode>("compress");
  const [sourcePath, setSourcePath] = useState("");
  const [sourceKind, setSourceKind] = useState<SourceKind>(null);
  const [outputPath, setOutputPath] = useState("");
  const [password, setPassword] = useState("");
  const [level, setLevel] = useState(6);
  const [warmupRuns, setWarmupRuns] = useState(1);
  const [measuredRuns, setMeasuredRuns] = useState(3);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<OperationResult | null>(null);
  const [benchmarkResult, setBenchmarkResult] = useState<BenchmarkResult | null>(null);
  const [progress, setProgress] = useState<ProgressPayload>({
    step: "idle",
    percentage: 0,
    message: "等待任务开始",
  });

  useEffect(() => {
    const unlisten = listen<ProgressPayload>("progress", (event) => {
      setProgress(event.payload);
    });
    return () => {
      unlisten.then((fn) => fn());
    };
  }, []);

  useEffect(() => {
    setError("");
    setResult(null);
    setBenchmarkResult(null);
    setProgress({ step: "idle", percentage: 0, message: "等待任务开始" });
    if (mode === "verify" || mode === "benchmark") {
      setOutputPath("");
    }
  }, [mode]);

  const outputIsRequired = mode === "compress" || mode === "decompress";
  const canRun = useMemo(() => {
    if (!sourcePath) return false;
    if (!outputIsRequired) return true;
    return Boolean(outputPath);
  }, [sourcePath, outputIsRequired, outputPath]);

  async function pickSourceFile() {
    const selected = await open({
      directory: false,
      multiple: false,
      title: mode === "compress" ? "选择待压缩文件" : "选择归档文件",
    });
    if (typeof selected === "string") {
      setSourcePath(selected);
      setSourceKind("file");
    }
  }

  async function pickSourceDirectory() {
    const selected = await open({
      directory: true,
      multiple: false,
      title: "选择待压缩目录",
    });
    if (typeof selected === "string") {
      setSourcePath(selected);
      setSourceKind("directory");
    }
  }

  async function pickOutput() {
    if (mode === "compress") {
      const ext =
        sourceKind === "directory"
          ? password.trim()
            ? ".tar.zst.enc"
            : ".tar.zst"
          : password.trim()
            ? ".zst.enc"
            : ".zst";

      const recommended = sourcePath ? `${sourcePath}${ext}` : `archive${ext}`;
      const target = await save({
        title: "保存归档文件",
        defaultPath: recommended,
      });
      if (typeof target === "string") setOutputPath(target);
      return;
    }

    if (isTarArchive(sourcePath)) {
      const folder = await open({
        directory: true,
        multiple: false,
        title: "选择解压输出目录",
      });
      if (typeof folder === "string") setOutputPath(folder);
      return;
    }

    const suggested = sourcePath ? stripArchiveSuffix(sourcePath) : "restored_output";
    const filePath = await save({
      title: "保存解压文件",
      defaultPath: suggested,
    });
    if (typeof filePath === "string") setOutputPath(filePath);
  }

  async function runTask() {
    if (!canRun || running) return;

    setRunning(true);
    setError("");
    setResult(null);
    setBenchmarkResult(null);

    try {
      if (mode === "compress") {
        const response = await invoke<OperationResult>("compress", {
          source: sourcePath,
          output: outputPath,
          password: password.trim() ? password : null,
          level,
        });
        setResult(response);
      } else if (mode === "decompress") {
        const response = await invoke<OperationResult>("decompress", {
          source: sourcePath,
          output: outputPath,
          password: password.trim() ? password : null,
        });
        setResult(response);
      } else if (mode === "verify") {
        const response = await invoke<OperationResult>("verify", {
          source: sourcePath,
          password: password.trim() ? password : null,
        });
        setResult(response);
      } else {
        const response = await invoke<BenchmarkResult>("benchmark_decompress", {
          source: sourcePath,
          password: password.trim() ? password : null,
          warmupRuns,
          measuredRuns,
        });
        setBenchmarkResult(response);
      }
    } catch (err) {
      setError(String(err));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="app-shell">
      <div className="glow glow-left" />
      <div className="glow glow-right" />

      <main className="panel">
        <header className="panel-header">
          <div className="brand">
            <div className="brand-icon">
              <Archive size={20} />
            </div>
            <div>
              <h1>ZARC Studio</h1>
              <p>现代化 Rust 归档工作台</p>
            </div>
          </div>
          <span className="badge">
            <Sparkles size={14} />
            高性能
          </span>
        </header>

        <section className="mode-switch">
          <button
            className={mode === "compress" ? "active" : ""}
            onClick={() => setMode("compress")}
          >
            <Upload size={15} />
            压缩
          </button>
          <button
            className={mode === "decompress" ? "active" : ""}
            onClick={() => setMode("decompress")}
          >
            <FileDown size={15} />
            解压
          </button>
          <button
            className={mode === "verify" ? "active" : ""}
            onClick={() => setMode("verify")}
          >
            <FileSearch size={15} />
            校验
          </button>
          <button
            className={mode === "benchmark" ? "active" : ""}
            onClick={() => setMode("benchmark")}
          >
            <Gauge size={15} />
            性能
          </button>
        </section>

        <section className="intro">
          <h2>{MODE_META[mode].title}</h2>
          <p>{MODE_META[mode].subtitle}</p>
        </section>

        <section className="form-grid">
          <div className="field">
            <label>
              <FileArchive size={14} />
              输入路径
            </label>
            <div className="field-row">
              <input
                value={sourcePath}
                onChange={(e) => setSourcePath(e.target.value)}
                placeholder={mode === "compress" ? "选择文件或目录..." : "选择归档文件..."}
              />
              {mode === "compress" ? (
                <>
                  <button className="icon-btn" onClick={pickSourceFile} title="选择文件">
                    <FileArchive size={16} />
                  </button>
                  <button className="icon-btn" onClick={pickSourceDirectory} title="选择目录">
                    <FolderOpen size={16} />
                  </button>
                </>
              ) : (
                <button className="icon-btn" onClick={pickSourceFile} title="选择归档文件">
                  <FolderOpen size={16} />
                </button>
              )}
            </div>
          </div>

          {mode !== "verify" && mode !== "benchmark" && (
            <div className="field">
              <label>
                <FolderOpen size={14} />
                输出路径
              </label>
              <div className="field-row">
                <input
                  value={outputPath}
                  onChange={(e) => setOutputPath(e.target.value)}
                  placeholder={mode === "compress" ? "保存归档到..." : "保存还原内容到..."}
                />
                <button className="icon-btn" onClick={pickOutput} title="选择输出路径">
                  <FolderOpen size={16} />
                </button>
              </div>
            </div>
          )}

          <div className="field">
            <label>
              <Lock size={14} />
              密码（可选）
            </label>
            <div className="field-row">
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={mode === "compress" ? "设置加密密码..." : "若为加密归档请填写..."}
              />
              <span className="inline-hint">
                <KeyRound size={14} />
              </span>
            </div>
          </div>

          {mode === "compress" && (
            <div className="field">
              <label>压缩等级（1-22）</label>
              <div className="level-row">
                <input
                  type="range"
                  min={1}
                  max={22}
                  value={level}
                  onChange={(e) => setLevel(Number(e.target.value))}
                />
                <strong>{level}</strong>
              </div>
            </div>
          )}

          {mode === "benchmark" && (
            <div className="field">
              <label>测试轮次</label>
              <div className="field-row">
                <input
                  type="number"
                  min={0}
                  max={10}
                  value={warmupRuns}
                  onChange={(e) => setWarmupRuns(Math.max(0, Number(e.target.value || 0)))}
                  placeholder="预热轮次"
                />
                <input
                  type="number"
                  min={1}
                  max={20}
                  value={measuredRuns}
                  onChange={(e) => setMeasuredRuns(Math.max(1, Number(e.target.value || 1)))}
                  placeholder="统计轮次"
                />
              </div>
            </div>
          )}
        </section>

        <section className="progress-panel">
          <div className="progress-head">
            <span>{progress.step.toUpperCase()}</span>
            <span>{Math.round(progress.percentage)}%</span>
          </div>
          <div className="progress-track">
            <div
              className="progress-value"
              style={{ width: `${Math.max(0, Math.min(100, progress.percentage))}%` }}
            />
          </div>
          <p>{progress.message}</p>
        </section>

        {error && (
          <section className="error-box">
            <strong>任务失败</strong>
            <p>{error}</p>
          </section>
        )}

        {result && (
          <section className="result-box">
            <div className="result-title">
              <CheckCircle2 size={16} />
              <strong>{result.message}</strong>
            </div>
            <div className="stats">
              <div>
                <span>输入大小</span>
                <strong>{formatBytes(result.input_bytes)}</strong>
              </div>
              <div>
                <span>结果大小</span>
                <strong>{formatBytes(result.result_bytes)}</strong>
              </div>
              <div>
                <span>耗时</span>
                <strong>{(result.duration_ms / 1000).toFixed(2)}s</strong>
              </div>
              <div>
                <span>比率</span>
                <strong>{result.ratio.toFixed(2)}%</strong>
              </div>
            </div>
            <code>{result.output_path}</code>
          </section>
        )}

        {benchmarkResult && (
          <section className="result-box">
            <div className="result-title">
              <CheckCircle2 size={16} />
              <strong>{benchmarkResult.message}</strong>
            </div>
            <div className="stats">
              <div>
                <span>压缩包大小</span>
                <strong>{formatBytes(benchmarkResult.archive_bytes)}</strong>
              </div>
              <div>
                <span>解压总量</span>
                <strong>{formatBytes(benchmarkResult.decompressed_bytes)}</strong>
              </div>
              <div>
                <span>平均耗时</span>
                <strong>{benchmarkResult.avg_duration_ms.toFixed(2)} ms</strong>
              </div>
              <div>
                <span>中位耗时</span>
                <strong>{benchmarkResult.median_duration_ms.toFixed(2)} ms</strong>
              </div>
              <div>
                <span>平均吞吐</span>
                <strong>{benchmarkResult.avg_throughput_mb_s.toFixed(2)} MB/s</strong>
              </div>
              <div>
                <span>最佳吞吐</span>
                <strong>{benchmarkResult.best_throughput_mb_s.toFixed(2)} MB/s</strong>
              </div>
            </div>
            <code>{benchmarkResult.source_path}</code>
          </section>
        )}

        <button className="run-btn" onClick={runTask} disabled={!canRun || running}>
          {running ? (
            <>
              <Loader2 size={18} className="spin" />
              处理中...
            </>
          ) : (
            <>
              <Play size={18} />
              {mode === "benchmark" ? "开始性能测试" : "立即执行"}
            </>
          )}
        </button>
      </main>
    </div>
  );
}
