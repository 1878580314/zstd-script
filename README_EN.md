# Zstandard Smart Toolbox

![Version](https://img.shields.io/badge/version-v2.3--Rich-blue.svg)
![Python Version](https://img.shields.io/badge/python-3.7+-brightgreen.svg)
![Dependencies](https://img.shields.io/badge/dependencies-rich%2C%20zstandard-orange.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

A powerful and user-friendly TUI (Text-based User Interface) for Zstandard compression, built with Python and the [Rich](https://github.com/Textualize/rich) library for a beautiful interactive terminal experience.

---

## 📖 About The Project

This tool aims to provide a simple and accessible command-line interface for the powerful [Zstandard](https://facebook.github.io/zstd/) compression algorithm. Whether you want to quickly compress a folder, decompress a file, or evaluate the performance of different compression levels, this toolbox makes the process intuitive and efficient with a clear menu and visual progress bars.

## ✨ Features

- ✅ **Smart Compression**: Automatically detects whether the input is a file or a folder. When compressing a folder, it intelligently archives it into a `.tar` file first, resulting in a `.tar.zst` archive.
- ✅ **Interactive TUI**: Powered by the Rich library, it offers an aesthetically pleasing menu, progress bars, tables, and highlighted text, moving beyond the traditional boring command line.
- ✅ **Comprehensive Toolkit**:
  - **Compress**: Supports custom compression levels (1-22) and utilizes all available CPU cores for multi-threaded compression.
  - **Decompress**: Intelligently handles both single `.zst` files and `.tar.zst` archives.
  - **Test**: Verifies the integrity of `.zst` archives to ensure data is not corrupted.
  - **List Info**: Quickly inspects an archive's metadata (like compression ratio, original/compressed size) without full decompression.
  - **Benchmark**: Performs a real-world benchmark on a file to visually compare the speed and compression ratios across different levels.
- ✅ **Drag & Drop Support**: In most modern terminals, you can simply drag and drop a file or folder onto the window to input its path.
- ✅ **Single-File Script**: All functionality is contained in a single Python script, making it easy to distribute and use.

## 📸 Visual Preview

**Main Menu:**

```
 Zstandard Smart Toolbox (v2.3-Rich)

 This is a fully self-contained tool with a built-in Zstandard engine.
 Tip: You can drag and drop files/folders into the window to enter paths.

 1. Compress a file or folder
 2. Decompress a file or archive
 3. Test an archive
 4. List archive info
 5. Real-world compression benchmark
 6. Exit

────────────────────────────────────────────────────────────────────────────
 Please enter your choice:
```

**Compression Progress:**

```
 Compressing   ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━  100.0% • 500.5/500.5 MB • 250.2 MB/s • 0:00:00
```

**Benchmark Results:**

```
                      Zstandard Compression Benchmark
┏━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━┳━━━━━━━━━━━━━━━━┓
┃ Level ┃ Ratio    ┃ Size     ┃ Speed          ┃
┡━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━╇━━━━━━━━━━━━━━━━┩
│ 1     │ 35.50%   │ 177.7 MB │ 650.1 MB/s     │
│ 2     │ 33.80%   │ 169.2 MB │ 580.3 MB/s     │
│ 3     │ 31.25%   │ 156.5 MB │ 490.7 MB/s     │
│ ...   │ ...      │ ...      │ ...            │
└───────┴──────────┴──────────┴────────────────┘
```

## 🚀 Getting Started

### 1. Prerequisites

- Python 3.7+
- `pip` package manager

### 2. Installation

Open your terminal and run the following command to install the necessary libraries:

```bash
pip install rich zstandard
```

### 3. Running the Tool

Save the code as `zstd_toolbox.py` (or any name you prefer), then launch it with:

```bash
python zstd_toolbox.py
```

The application will start and display the main menu. Simply enter a number to select the desired function.

## 🛠️ Functionality in Detail

1.  **Compress a file or folder**

    - Provide the path to a file or folder.
    - Enter a compression level (1-22, default is 3). Higher levels yield better compression ratios but are slower.
    - The program will start compressing and display a real-time progress bar.

2.  **Decompress a file or archive**

    - Provide the path to a `.zst` or `.tar.zst` file.
    - The tool will automatically detect the type and decompress it to the current directory.

3.  **Test an archive**

    - Input a `.zst` or `.tar.zst` file.
    - The tool will attempt to decompress the data stream to check for corruption without writing the output to disk.

4.  **List archive info**

    - Input a `.zst` file.
    - The tool quickly reads the file header and displays information like compressed size, original size, and compression ratio in a table.

5.  **Real-world compression benchmark**
    - Provide a large file to serve as a test sample.
    - The tool will compress it using levels 1 through 19, measuring the speed and compression ratio for each. This helps you find the perfect trade-off between speed and size for your needs.

## 📄 License

This project is licensed under the [MIT License](LICENSE).
