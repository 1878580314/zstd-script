# Zstandard Smart Toolbox

![Version](https://img.shields.io/badge/version-v3.0--Nexus-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.8+-brightgreen.svg)
![Dependencies](https://img.shields.io/badge/dependencies-rich%2C%20zstandard%2C%20cryptography*-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

> A high-performance, memory-aware terminal UI for Zstandard compression, powered by Python, [Rich](https://github.com/Textualize/rich), and optional AES-256-GCM encryption.

---

## 📖 Overview

`zstd.py` wraps the Zstandard codec with an approachable interactive CLI. Rich-powered progress bars and prompts guide you through everyday compression, decompression, and archive verification tasks. Install the `cryptography` package to unlock seamless encryption and decryption flows.

## ✨ Highlights

- ✅ **Smart compression**: Works with individual files or whole folders. When a directory is selected, it streams a `tar` archive directly into a `.tar.zst` output—no temporary staging required.
- ✅ **Optional encryption**: With `cryptography` installed, enable AES-256-GCM to protect results. Encrypted outputs use the `.enc` suffix and require the same password to restore.
- ✅ **Fast extraction**: Detects `.zst`, `.tar.zst`, and encrypted `.enc` inputs automatically, creating a destination folder when unpacking archives.
- ✅ **Integrity checks**: Stream-verify `.zst` payloads to catch corruption early (decrypt encrypted files first).
- ✅ **Rich terminal feedback**: Animated progress, warning panels, and summary tables make each operation transparent.

## 📸 Menu Preview

```
 Zstandard 智能工具箱 (Nexus 重构版)

 A high-performance, memory-efficient compression tool
 Tip: Drag files or folders into the window to populate paths

 1. Compress a file or folder (optional encryption)
 2. Decompress a file or archive (auto decrypt)
 3. Test a compressed file (encrypted files unsupported)
 4. Exit

────────────────────────────────────────────────────────
 Please enter your choice:
```

## 🚀 Getting Started

### 1. Install dependencies

Use the provided `requirements.txt` for the core stack:

```bash
pip install -r requirements.txt
```

Install `cryptography` to enable encryption and decryption:

```bash
pip install cryptography
```

### 2. Launch the toolbox

Run the script from the project root:

```bash
python zstd.py
```

Follow the menu prompts; most modern terminals also accept drag-and-drop paths.

## 🛠️ Usage Guide

**Compress a file or folder**
- Supply the target path and choose a compression level (1-22, default 3).
- When encryption is enabled, enter and confirm the password. Outputs end with `.zst` or `.tar.zst.enc`.
- A summary panel shows source size, result size, and compression ratio on completion.

**Decompress a file or archive**
- Supports `.zst`, `.tar.zst`, and `.enc` files.
- Encrypted files prompt for the password; directory archives extract into a `*_解压后` folder.

**Test a compressed file**
- Stream-verify unencrypted `.zst` archives without writing intermediary data.
- Rename or decrypt `.enc` files via the “Decompress” flow before running tests.

## ⚙️ Implementation Notes

- Relies on the official Zstandard Python bindings with multi-threaded compression by default.
- Directory compression streams data to keep memory usage predictable.
- Directory extraction reads the compressed payload into memory; ensure you have enough disk space for the output.
- On Windows consoles the window title updates automatically for clarity.

## 📄 License

Released under the [MIT License](LICENSE). Contributions and forks are welcome.
