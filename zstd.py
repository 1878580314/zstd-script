import os
import sys
import time
import math
from pathlib import Path
import zstandard as zstd
import tarfile

# --- 全局设置 ---
TITLE = "Zstandard 智能工具箱 v3.0 (完全独立版, 含实时状态)"

# --- 辅助函数 ---


def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")


def pause(message="按 Enter 键返回主菜单..."):
    input(message)


def human_readable_size(size_bytes):
    if size_bytes == 0:
        return "0B"
    size_name = ("B", "KB", "MB", "GB", "TB")
    i = 0
    size = float(size_bytes)
    while size >= 1024 and i < len(size_name) - 1:
        size /= 1024.0
        i += 1
    return f"{size:.2f} {size_name[i]}"


# ===== 实时进度支持（零依赖） =====


def format_seconds(sec):
    if sec is None or math.isinf(sec) or sec < 0:
        return "??:??"
    m, s = divmod(int(sec + 0.5), 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}"


class Progress:
    """
    total: 原始总字节数（未知则为 None）
    processed: 已处理的原始字节
    secondary: 次级计数（这里用来记录“压缩后字节数”）
    """

    def __init__(self, total=None, title=""):
        self.total = total
        self.title = title
        self.start = time.perf_counter()
        self.last_draw = 0.0
        self.processed = 0
        self.secondary = 0
        self._line_len = 0

    def update(self, inc, secondary_inc=0):
        self.processed += inc
        self.secondary += secondary_inc
        now = time.perf_counter()
        # 100ms 刷新一次
        if now - self.last_draw >= 0.10:
            self.draw(now)

    def draw(self, now=None, done=False):
        if now is None:
            now = time.perf_counter()
        elapsed = now - self.start
        speed = self.processed / elapsed if elapsed > 0 else 0.0  # B/s

        if self.total and self.total > 0:
            pct = min(100.0, self.processed * 100.0 / self.total)
            remain = max(0.0, (self.total - self.processed))
            eta = remain / speed if speed > 0 else None
            bar_len = 24
            filled = int(bar_len * pct / 100.0)
            bar = "█" * filled + "…" * (bar_len - filled)
            left = f"{pct:6.2f}% [{bar}]"
        else:
            eta = None
            left = "   N/A  [进度未知]"

        ratio = (
            (self.secondary / self.processed * 100.0)
            if self.processed > 0 and self.secondary > 0
            else None
        )
        ratio_txt = f"{ratio:6.2f}%" if ratio is not None else "   N/A "

        def hsize(n):
            return human_readable_size(int(n))

        line = (
            f"{self.title} "
            f"{left}  |  速率: {hsize(speed)}/s"
            f"  已处理: {hsize(self.processed)}"
            f"  压缩后: {hsize(self.secondary)}"
            f"  压缩率: {ratio_txt}"
            f"  用时: {format_seconds(elapsed)}"
            f"  剩余: {format_seconds(eta)}"
        )

        pad = max(0, self._line_len - len(line))
        sys.stdout.write("\r" + line + " " * pad)
        sys.stdout.flush()
        self._line_len = len(line)
        self.last_draw = now

        if done:
            sys.stdout.write("\n")
            sys.stdout.flush()


class CountingWriter:
    """包裹写入端（通常是输出文件/管道），累计写入字节并刷新 secondary。"""

    def __init__(self, raw, progress=None):
        self.raw = raw
        self.count = 0
        self.progress = progress

    def write(self, b):
        n = self.raw.write(b)
        self.count += n
        if self.progress:
            self.progress.update(0, secondary_inc=n)  # 压缩后字节
        return n

    def flush(self):
        return self.raw.flush()

    def close(self):
        return self.raw.close()

    def fileno(self):
        return self.raw.fileno()


class ReadProgressFile:
    """包裹读取端（通常是输入文件），每次 read 推进度（原始字节）。"""

    def __init__(self, raw, progress):
        self.raw = raw
        self.progress = progress

    def read(self, size=-1):
        b = self.raw.read(size)
        if b:
            self.progress.update(len(b), 0)
        return b

    def close(self):
        return self.raw.close()


# --- 功能实现 (使用 zstandard 库) ---


def compress():
    clear_screen()
    print("--- 智能压缩 [文件/文件夹] (内置引擎 + 实时状态) ---\n")

    input_path_str = input("请输入要压缩的文件或文件夹名: ").strip('"')
    input_path = Path(input_path_str)

    if not input_path.exists():
        print(f"\n错误: 路径 '{input_path}' 不存在!")
        pause()
        return

    level_str = input("请输入压缩级别 (1-22, 默认为 3): ")
    level = int(level_str) if level_str.isdigit() else 3

    # 创建一个支持多线程的压缩器
    cctx = zstd.ZstdCompressor(level=level, threads=-1)

    if input_path.is_dir():
        output_file = input_path.with_suffix(".tar.zst")
        print(f"\n正在压缩文件夹 '{input_path}' 到 '{output_file}'...\n")
        try:
            # 1) 预统计总大小（仅普通文件）
            file_list = []
            total_bytes = 0
            base = input_path.resolve()
            for root, dirs, files in os.walk(base):
                for name in files:
                    p = Path(root) / name
                    try:
                        st = p.stat()
                        if not p.is_symlink():
                            total_bytes += st.st_size
                            file_list.append(p)
                    except FileNotFoundError:
                        pass  # 跳过不可达文件

            prog = Progress(total=total_bytes, title="压缩目录")
            with open(output_file, "wb") as f_out_raw:
                sink = CountingWriter(f_out_raw, progress=prog)
                with cctx.stream_writer(sink) as compressor:
                    # 流式 tar 打包
                    with tarfile.open(fileobj=compressor, mode="w|") as tar:
                        # 写入根目录条目（不递归），文件会单独追加
                        tar.add(str(base), arcname=base.name, recursive=False)
                        # 逐文件 addfile，并以 ReadProgressFile 统计原始字节
                        for fp in file_list:
                            # 使存档路径包含 base.name（与常规 tar -C 保持一致）
                            rel = fp.resolve().relative_to(base.parent)
                            info = tar.gettarinfo(str(fp), arcname=str(rel))
                            if info is None:
                                continue
                            with open(fp, "rb") as fin:
                                tar.addfile(info, fileobj=ReadProgressFile(fin, prog))

            prog.draw(done=True)
            print("\n操作成功!")
        except Exception as e:
            print(f"\n压缩失败: {e}")
    else:
        output_file = input_path.with_suffix(input_path.suffix + ".zst")
        print(f"\n正在压缩文件 '{input_path}' 到 '{output_file}'...\n")
        try:
            total = input_path.stat().st_size
            prog = Progress(total=total, title="压缩单文件")
            CHUNK = 1 << 20  # 1 MiB

            with open(input_path, "rb") as f_in, open(output_file, "wb") as f_out_raw:
                sink = CountingWriter(f_out_raw, progress=prog)
                with cctx.stream_writer(sink) as compressor:
                    while True:
                        data = f_in.read(CHUNK)
                        if not data:
                            break
                        # 原始已处理字节
                        prog.update(len(data), 0)
                        compressor.write(data)

            prog.draw(done=True)
            print("\n操作成功!")
        except Exception as e:
            print(f"\n压缩失败: {e}")

    pause()


def decompress():
    clear_screen()
    print("--- 智能解压 (.zst / .tar.zst) (内置引擎 + 实时状态) ---\n")

    input_file_str = input("请输入要解压的文件名: ").strip('"')
    input_file = Path(input_file_str)

    if not input_file.is_file():
        print(f"\n错误: 文件 '{input_file}' 不存在!")
        pause()
        return

    dctx = zstd.ZstdDecompressor()

    # 尝试读取帧头声明的 content_size（可能未知）
    def probe_content_size(p: Path):
        try:
            with open(p, "rb") as f:
                header = f.read(18)  # 最长帧头
            params = zstd.get_frame_parameters(header)
            return params.content_size if params.content_size > 0 else None
        except Exception:
            return None

    if input_file.name.lower().endswith(".tar.zst"):
        print(f"\n正在解压归档 '{input_file}' 到当前目录...\n")
        try:
            declared = probe_content_size(input_file)  # 可能为 None（未知总量）
            prog = Progress(total=declared, title="解压 .tar.zst")

            with open(input_file, "rb") as f_in:
                reader = dctx.stream_reader(f_in)

                class CountingReader:
                    def __init__(self, raw, prog: Progress):
                        self.raw = raw
                        self.prog = prog

                    def read(self, size=-1):
                        b = self.raw.read(size)
                        if b:
                            # 这里的 b 是“解压后 tar 字节”
                            self.prog.update(len(b), 0)
                        return b

                    def close(self):
                        return self.raw.close()

                cr = CountingReader(reader, prog)

                # 流式读取 tar
                with tarfile.open(fileobj=cr, mode="r|") as tar:
                    for member in tar:
                        tar.extract(member)

            prog.draw(done=True)
            print("\n操作成功!")
        except Exception as e:
            print(f"\n解压失败: {e}")

    elif input_file.name.lower().endswith(".zst"):
        output_file = input_file.with_suffix("")
        print(f"\n正在解压文件 '{input_file}' 到 '{output_file}'...\n")
        try:
            total = probe_content_size(input_file)  # 若 None，显示 N/A 进度
            prog = Progress(total=total, title="解压单文件")
            CHUNK = 1 << 20
            with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
                with dctx.stream_reader(f_in) as reader:
                    while True:
                        data = reader.read(CHUNK)
                        if not data:
                            break
                        f_out.write(data)
                        # data 为“解压后的原始字节”
                        prog.update(len(data), 0)

            prog.draw(done=True)
            print("\n操作成功!")
        except Exception as e:
            print(f"\n解压失败: {e}")
    else:
        print("\n错误: 不支持的文件类型。请选择 .zst 或 .tar.zst 文件。")

    pause()


def test_archive():
    clear_screen()
    print("--- 测试压缩文件完整性 (内置引擎) ---\n")
    input_file_str = input("请输入要测试的 .zst 文件名: ").strip('"')
    input_file = Path(input_file_str)

    if not input_file.is_file():
        print(f"\n错误: 文件 '{input_file}' 不存在!")
        pause()
        return

    print(f"\n正在测试文件: {input_file}...")
    try:
        dctx = zstd.ZstdDecompressor()
        with open(input_file, "rb") as f_in, open(os.devnull, "wb") as f_out:
            dctx.copy_stream(f_in, f_out)
        print("测试结果: 文件完整，没有错误。")
    except zstd.ZstdError as e:
        print(f"测试结果: 文件已损坏! 错误: {e}")
    except Exception as e:
        print(f"测试期间发生未知错误: {e}")

    print("\n测试完成。\n")
    pause()


def list_info():
    clear_screen()
    print("--- 查看压缩文件信息 (内置引擎) ---\n")
    input_file_str = input("请输入要查看信息的 .zst 文件名: ").strip('"')
    input_file = Path(input_file_str)

    if not input_file.is_file():
        print(f"\n错误: 文件 '{input_file}' 不存在!")
        pause()
        return

    try:
        with open(input_file, "rb") as fh:
            # 读取 zstd 魔法数字和帧头
            fh.seek(0)
            frame_header = zstd.get_frame_parameters(fh.read(18))
            compressed_size = input_file.stat().st_size
            ratio = (
                (compressed_size / frame_header.content_size) * 100
                if frame_header.content_size > 0
                else 0
            )

            print("\n----------------------------------------------------------")
            print(f"  文件名: {input_file.name}")
            print(f"  压缩后大小: {human_readable_size(compressed_size)}")
            print(f"  解压后大小: {human_readable_size(frame_header.content_size)}")
            if ratio > 0:
                print(f"  压缩率: {100/ratio:.2f}x ({ratio:.2f}%)")
            else:
                print("  压缩率: N/A（帧头未声明 content_size）")
            print(f"  字典 ID: {frame_header.dict_id or '无'}")
            print("----------------------------------------------------------")

    except zstd.ZstdError as e:
        print(f"\n无法分析文件: {e}. 可能不是一个有效的 zstd 文件。")
    except Exception as e:
        print(f"\n发生错误: {e}")

    pause()


def real_benchmark():
    clear_screen()
    print("--- 真实文件压缩性能测试 (逐级 1-19) (内置引擎) ---\n")

    input_path_str = input("请输入要测试的文件: ").strip('"')
    input_path = Path(input_path_str)

    if not input_path.is_file():
        print(f"\n错误: 路径 '{input_path}' 不是一个有效的文件!")
        pause()
        return

    print(
        "\n-------------------------------------------------------------------------------"
    )
    print(f"  测试目标: {input_path}")
    print("  测试将在所有核心上运行。请稍候...")
    print(
        "-------------------------------------------------------------------------------\n"
    )
    print(" 级别 | 压缩率     | 压缩后大小       | 原始大小         | 压缩速度")
    print(
        "======|==============|==================|==================|================"
    )

    try:
        original_data = input_path.read_bytes()
        original_size = len(original_data)

        for level in range(1, 20):
            cctx = zstd.ZstdCompressor(level=level, threads=-1)

            start_time = time.perf_counter()
            compressed_data = cctx.compress(original_data)
            end_time = time.perf_counter()

            duration = end_time - start_time
            compressed_size = len(compressed_data)
            speed = (original_size / duration) / (1024 * 1024)  # MB/s
            ratio = (compressed_size / original_size) * 100 if original_size > 0 else 0

            # 格式化输出
            level_str = f" {level:<5}"
            ratio_str = f"{ratio:6.2f}%"
            c_size_str = f"{human_readable_size(compressed_size):<16}"
            o_size_str = f"{human_readable_size(original_size):<16}"
            speed_str = f"{speed:.2f} MB/s"

            print(
                f"{level_str}| {ratio_str:<12} | {c_size_str} | {o_size_str} | {speed_str}"
            )

    except Exception as e:
        print(f"\n测试过程中发生错误: {e}")

    print(
        "===============================================================================\n"
    )
    print("  提示: 更高压缩率的 --ultra 级别 (20-22) 因速度较慢未包含在此测试中。\n")
    pause()


def main_menu():
    """显示主菜单并处理用户选择"""
    while True:
        clear_screen()
        if sys.platform == "win32":
            os.system(f"title {TITLE}")

        print(f"\n==========================================================")
        print(f"          {TITLE}")
        print("==========================================================\n")
        print("  这是一个完全独立的工具，无需额外依赖\n")
        print("  操作提示: 可以直接将文件或文件夹拖拽到此窗口来输入路径\n")
        print("----------------------------------------------------------\n")
        print("  1. 压缩文件或文件夹 (智能识别, 实时状态)")
        print("  2. 解压文件或归档 (智能识别 .zst / .tar.zst, 实时状态)")
        print("  3. 测试压缩文件 (检查文件是否损坏)")
        print("  4. 查看压缩文件信息")
        print("  5. 真实文件压缩性能测试 (逐级 1-19)")
        print("  6. 退出\n")
        print("----------------------------------------------------------")

        choice = input("\n请输入您的选择 [1-6], 然后按 Enter: ")

        actions = {
            "1": compress,
            "2": decompress,
            "3": test_archive,
            "4": list_info,
            "5": real_benchmark,
            "6": sys.exit,
        }

        action = actions.get(choice)
        if action:
            action()
        else:
            print("\n无效的选择，请按任意键返回主菜单...")
            pause()


# --- 程序入口 ---
if __name__ == "__main__":
    main_menu()
