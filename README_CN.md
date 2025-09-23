# Zstandard 智能工具箱

![版本](https://img.shields.io/badge/version-v3.0--Nexus-blue.svg)
![Python 版本](https://img.shields.io/badge/python-3.8+-brightgreen.svg)
![依赖](https://img.shields.io/badge/dependencies-rich%2C%20zstandard%2C%20cryptography*-orange.svg)
![许可证](https://img.shields.io/badge/license-MIT-green.svg)

> 一个高性能、内存友好的 Zstandard 压缩终端工具，基于 Python 和 [Rich](https://github.com/Textualize/rich) 打造，并提供可选的 AES-256-GCM 加密能力。

---

## 📖 项目简介

`zstd.py` 将 Zstandard 的压缩能力封装成一款简单易用的交互式命令行工具。界面包含动效进度条与友好的提示，引导你完成日常常见的压缩、解压、验包任务。如果安装了 `cryptography` 模块，还可以在压缩时快速加密，或在解压时自动解密。

## ✨ 功能特性

- ✅ **智能压缩**：支持文件与文件夹。压缩目录时会先打包为 `tar` 流，再实时压缩为 `.tar.zst`，无需额外中间文件。
- ✅ **可选加密**：如已安装 `cryptography`，可使用 AES-256-GCM 对压缩结果加密，生成 `.enc` 文件，保障隐私数据安全。
- ✅ **快速解压**：自动识别 `.zst`、`.tar.zst` 以及加密的 `.enc` 文件；解压目录时自动创建输出文件夹。
- ✅ **完整性校验**：针对 `.zst` 文件提供流式校验，快速发现损坏数据（加密文件请先解密）。
- ✅ **丰富的终端反馈**：通过 Rich 渲染进度条、表格、提示面板，实时展示处理进度与压缩摘要。

## 📸 菜单预览

```
 Zstandard 智能工具箱 (Nexus 重构版)

 一个高性能、高内存效率的压缩工具
 操作提示: 可直接将文件/文件夹拖拽到窗口输入路径

 1. 压缩文件或文件夹 (可选加密)
 2. 解压文件或归档 (自动解密)
 3. 测试压缩文件 (不支持加密文件)
 4. 退出

────────────────────────────────────────────────────────
 请输入您的选择:
```

## 🚀 快速开始

### 1. 安装依赖

项目提供 `requirements.txt`，默认安装核心依赖：

```bash
pip install -r requirements.txt
```

如需启用加密/解密能力，请额外安装：

```bash
pip install cryptography
```

### 2. 运行工具

在项目目录执行：

```bash
python zstd.py
```

根据菜单提示输入编号即可完成对应操作。支持在大多数终端中直接拖拽文件或文件夹路径。

## 🛠️ 使用说明

**压缩文件或文件夹**
- 输入待压缩路径，并选择压缩等级（1-22，默认 3）。
- 若启用加密，需输入并确认密码，最终输出为 `.zst` 或 `.tar.zst.enc`。
- 完成后会显示原始大小、压缩后大小及压缩比摘要。

**解压文件或归档**
- 支持 `.zst`、`.tar.zst` 以及 `.enc` 文件。
- 对加密文件会先提示输入密码，成功后自动解压到当前目录（目录归档会创建 `*_解压后/`）。

**测试压缩文件**
- 对未加密的 `.zst` 文件执行流式校验，不生成输出文件。
- 若目标以 `.enc` 结尾，请先通过“解压”流程解密。

## ⚙️ 设计要点

- 使用 Zstandard 官方 Python 绑定，压缩默认开启多线程。
- 目录压缩采用流式写入，降低内存占用。
- 解压目录时会一次性读取压缩数据，请确保磁盘空间充足。
- Windows 终端会自动更新标题栏，增强辨识度。

## 📄 许可证

本项目基于 [MIT License](LICENSE) 发布，可自由使用与二次开发。
