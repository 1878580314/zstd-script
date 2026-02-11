# ZARC Studio (Rust + Tauri)

现代化、高性能、轻量化的桌面归档工具，核心能力已迁移到 Rust 技术栈：

- 流式 `zstd` 压缩与解压
- 可选流式 `AES-256-GCM` 加密（`ZARCv2` 格式）
- 归档完整性校验（无需落盘提取）
- 解压缩性能测试（预热 + 多轮统计 + 吞吐结果）
- 精致现代化桌面 UI（Tauri + React）

## 项目结构

- `zarc-desktop/src-tauri`: Rust 核心后端（压缩 / 解压 / 校验）
- `zarc-desktop/src-tauri`: Rust 核心后端（压缩 / 解压 / 校验 / 性能测试）
- `zarc-desktop/src`: 桌面前端 UI
- `zstd.py`: 历史 Python 版本（保留作参考）

## 功能说明

1. 压缩模式
- 支持文件压缩为 `.zst`
- 支持目录打包压缩为 `.tar.zst`
- 可选加密输出为 `.enc`

2. 解压模式
- 自动识别加密头 `ZARCv2`
- 自动支持 `.zst` / `.tar.zst` / `.enc`

3. 校验模式
- 流式验证归档可读性
- 加密归档会校验密码与认证标签

4. 性能测试模式
- 针对解压缩流程做基准测试（默认 1 轮预热 + 3 轮统计）
- 输出平均值/中位数/最优吞吐（MB/s）
- 测试时写入 `sink`，避免落盘写入开销干扰解压缩性能

## 本地运行

Linux（Arch）先安装系统依赖：

```bash
sudo pacman -Syu --needed webkit2gtk libsoup gtk3 base-devel pkgconf
```

前端依赖安装：

```bash
cd zarc-desktop
npm install
```

开发模式：

```bash
npm run tauri dev
```

默认打包：

```bash
npm run tauri build
```

## 全平台可执行文件打包（优化版）

本项目已配置为 Tauri 全平台发布流：

- Linux: `.deb` + `.AppImage`
- Windows: `.msi`
- macOS: `.dmg`

### 本地按平台打包

```bash
cd zarc-desktop
npm run tauri:bundle:linux
npm run tauri:bundle:windows
npm run tauri:bundle:macos
```

产物目录：

- `zarc-desktop/src-tauri/target/release/bundle/deb`
- `zarc-desktop/src-tauri/target/release/bundle/appimage`
- `zarc-desktop/src-tauri/target/release/bundle/msi`
- `zarc-desktop/src-tauri/target/release/bundle/dmg`

### GitHub Actions 自动发布

工作流：`.github/workflows/release.yml`

- 推送标签 `v*`（如 `v2.1.0`）会自动触发三平台构建
- 自动将产物上传并附加到 GitHub Release

示例：

```bash
git tag v2.1.1
git push origin v2.1.1
```

### Linux AppImage 常见问题（Arch）

若本地打包 `AppImage` 时报错（如 `unknown type [0x13] section '.relr.dyn'`），通常是本机系统库与 linuxdeploy 内置 strip 兼容性问题。

建议：

1. 本地先产出 `.deb`（稳定）
2. `AppImage` 交给 GitHub Actions 的 Ubuntu Runner 生成
3. 或在 Ubuntu 容器/虚拟机中打包 `AppImage`

## 说明

- 本仓库当前环境若离线，`cargo`/`npm` 依赖下载会失败；联网后即可正常构建。
- Rust release 配置已启用 `LTO + strip + codegen-units=1`，兼顾性能与体积。
- Rust 后端命令：
  - `compress(source, output, password?, level?)`
  - `decompress(source, output, password?)`
  - `verify(source, password?)`
  - `benchmark_decompress(source, password?, warmup_runs?, measured_runs?)`
