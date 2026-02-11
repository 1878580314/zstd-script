# ZARC Studio

该仓库已重构为 `Rust + Tauri` 桌面应用，提供：

- 高性能 `zstd` 压缩与解压
- 文件与目录归档（目录打包为 `.tar.zst`）
- 高性能加密归档（`XChaCha20-Poly1305 + Argon2id`）
- 压缩/解压实时进度条（百分比、吞吐、ETA）
- 快速压缩性能测试（多等级对比并推荐压缩等级）
- 浅色系、轻量化跨平台 UI

## 开发运行

```bash
cd zarc-desktop
npm install
npm run tauri dev
```

## 打包

```bash
cd zarc-desktop
npm install
npm run tauri build
```

## Windows 打包 (优化)

在 Windows 10/11 环境中执行：

```powershell
cd zarc-desktop
npm install
npm run tauri:build:win
```

产物默认位于（便携版 EXE）：

- `zarc-desktop/src-tauri/target/release/zarc-desktop.exe`

如需便携分发，可将 EXE 压缩为 zip 后直接分发。

本项目已启用发布优化（`LTO + strip + panic=abort + codegen-units=1`），用于提升性能并减小安装包体积。

## GitHub 自动构建与发布

仓库已配置跨平台自动构建工作流：

- `push main`：自动构建 Linux(`.deb/.AppImage`) + Windows(`portable .zip`) + macOS(`.dmg`) 并上传为 Actions artifacts
- `pull_request -> main`：自动执行同样的三平台构建校验
- `push tag v*`：构建三平台产物并自动创建 GitHub Release，附带安装包
- `workflow_dispatch`：可手动触发一次完整构建/发布流程

## WSL 图形驱动告警排障

如果出现以下日志：

- `libEGL warning: failed to get driver name for fd -1`
- `MESA: error: ZINK: vkEnumeratePhysicalDevices failed`
- `egl: failed to create dri2 screen`

可使用软件渲染模式启动：

```bash
cd zarc-desktop
npm run tauri:dev:wsl
```

如果你希望继续使用硬件加速，请先在 Windows 侧更新 WSLg 与显卡驱动，然后重启 WSL：

```powershell
wsl --update
wsl --shutdown
```

## 快速压缩测试说明

在 UI 的“快速压缩性能测试”中：

- 选择文件或目录作为测试源
- 设置等级区间（如 `1~12`）
- 程序基于可配置样本大小进行快速多等级压缩对比
- 输出每个等级的吞吐、压缩率，并自动给出推荐等级

## 加密说明

- 压缩时勾选“启用加密”并输入密码，归档将生成为 `.enc`
- 解压 `.enc` 归档时需输入正确密码
- 算法：`XChaCha20-Poly1305`（分块 AEAD）+ `Argon2id` 密钥派生

## 加解密测试覆盖

已在 Rust 单元测试中覆盖：

- 文件类型：文本、JSON、二进制、空文件、Unicode 文件名
- 文件大小：`0B`、小文件、`chunk-1`、`chunk`、`chunk+1`、多 chunk 大文件
- 目录场景：`include_root_dir=true/false` 两种归档布局
- 安全性：错误密码解密失败校验
- 回归：未加密归档压缩/解压流程仍正常
