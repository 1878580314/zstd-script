# Zstandard Intelligent Toolbox · Zstandard 智能工具箱

## Overview / 项目简介
Zstandard Intelligent Toolbox is an interactive CLI that wraps Facebook's Zstandard codec with rich terminal feedback, optional AES-256-GCM encryption, and streaming-friendly workflows. It targets power users who need fast compression for single files or entire folders without sacrificing usability.

Zstandard 智能工具箱是一款交互式命令行工具，基于 Facebook 的 Zstandard 编解码器，配合 Rich 终端组件提供可视化提示，同时支持可选的 AES-256-GCM 加密与流式处理，帮助你在追求性能的同时保持易用体验。

## Highlights / 功能特性
- **Compression & archiving**: Compress individual files or whole directories; folders are transparently tarred and compressed into `.tar.zst` outputs.
- **Streaming AES-256-GCM**: Encryption/decryption now works in constant memory, so archives no longer need to fit in RAM and can exceed 64 GB limits.
- **Rich UX**: Progress bars, summaries, and prompts are rendered via `rich` for a polished workflow.
- **Integrity tests**: Validate `.zst` archives without extracting data; encrypted archives can be verified after decryption.
- **Cross-platform ready**: Works on macOS/Linux/Windows; GitHub Actions builds Windows and Linux distributables automatically.
-
- **智能压缩与归档**：支持文件与目录，目录会自动打包为 `.tar.zst`，无需中间文件。
- **流式 AES-256-GCM**：加/解密全过程皆为流式处理，不占用额外内存，也不再受 64 GB 单次限制影响。
- **丰富的终端体验**：借助 `rich` 展示进度条、摘要与提示，交互体验更友好。
- **完整性校验**：无需解压即可验证 `.zst` 文件；加密包解密后亦可校验。
- **跨平台准备就绪**：适配 macOS/Linux/Windows，并通过 GitHub Actions 自动构建 Windows 与 Linux 发行包。

## Requirements / 环境要求
- Python 3.10+ (due to the use of modern type hints and structural pattern handling).
- `zstandard`, `rich`; `cryptography` is optional but required for encryption/decryption features.
- On Windows, use PowerShell or compatible terminals for Unicode output.

Python 版本需 3.10 及以上；依赖 `zstandard`、`rich`，如需加解密能力需额外安装 `cryptography`。Windows 用户建议使用支持 Unicode 的 PowerShell 或终端。

## Installation / 安装
```bash
python -m pip install --upgrade pip
pip install zstandard rich  # 加密功能请同时安装 cryptography
pip install cryptography    # 可选
```

## Usage / 使用指南
1. Launch the toolbox:
   ```bash
   python zstd.py
   ```
2. Follow the interactive menu to:
   - Compress files/folders (optionally encrypting them).
   - Decompress `.zst`, `.tar.zst`, or `.enc` archives.
   - Test archive integrity.
3. Drag & drop paths into the prompt if your terminal supports it.

使用步骤：
1. 执行 `python zstd.py` 进入主菜单。
2. 按提示选择功能：压缩文件/目录、解压 `.zst`/`.tar.zst`/`.enc`、或测试压缩包。
3. 支持拖拽路径到终端输入框，省去手动输入。

### Encryption Notes / 加密说明
- When prompted, enable encryption and enter a strong passphrase; confirmation is required to avoid typos.
- Decryption requests the same password and validates the GCM authentication tag. Errors indicate a wrong password or corrupted data.
- Streaming encryption removes the previous requirement to buffer full archives, making multi-gigabyte encrypted backups practical.

启用加密时需要输入并确认密码；解密时若认证失败，会提示密码错误或文件损坏。流式实现无需再缓存完整文件，适用于 TB 级数据归档。

## Development / 开发指南
1. Create and activate a virtual environment.
2. Install development dependencies:
   ```bash
   pip install zstandard rich cryptography
   ```
3. Run the toolbox locally using `python zstd.py` and exercise the desired workflow.
4. Ensure `python -m compileall zstd.py` succeeds before committing.

## Building Binaries / 构建独立可执行文件
Manual builds rely on [PyInstaller](https://pyinstaller.org/):
```bash
pip install pyinstaller
pyinstaller --onefile --name zstd zstd.py
```
Artifacts appear under `dist/` (`zstd` on Linux/macOS, `zstd.exe` on Windows).

通过 PyInstaller 可快速生成独立可执行文件，命令如上。输出位于 `dist/` 目录（Linux/macOS 生成 `zstd`，Windows 生成 `zstd.exe`）。

## Continuous Delivery / 持续交付
- The project ships with a GitHub Actions workflow (`.github/workflows/release.yml`).
- Builds trigger on tag pushes (`v*`) or manual dispatch, producing Windows & Linux binaries.
- Artifacts are archived (`.zip` on Windows, `.tar.gz` on Linux) and attached to GitHub Releases automatically.

项目提供 GitHub Actions 工作流（`.github/workflows/release.yml`）：
- 当推送 `v*` 标签或手动触发时，会在 Windows 与 Linux 上构建可执行文件。
- 构建结果分别打包为 `.zip`（Windows）和 `.tar.gz`（Linux），并自动上传至 GitHub Releases。

## License / 许可证
Unless otherwise noted, the project is distributed under the MIT License.

除特殊说明外，本项目以 MIT 许可证发布，欢迎自由使用与二次开发。
