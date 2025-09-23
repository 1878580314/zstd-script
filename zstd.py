# -*- coding: utf-8 -*-
"""
Zstandard Intelligent Toolbox (Refactored by Nexus)
=============================================================
A high-performance, memory-efficient command-line tool for file/folder
operations using Zstandard, with optional AES-256-GCM encryption.
"""

import os
import sys
import tarfile
import time
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, Callable, Generator, List

import zstandard as zstd
from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    FileSizeColumn,
    Progress,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.rule import Rule
from rich.table import Table

# --- Cryptography Module ---
try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# --- Constants ---
TITLE = "Zstandard 智能工具箱 (Nexus 重构版)"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 480_000
CHUNK_SIZE = 1024 * 1024  # 1MB chunks for streaming


# --- Cryptography Helpers ---
def derive_key(password: str, salt: bytes) -> bytes:
    """Securely derive a key from a password and salt."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(data: bytes, password: str) -> bytes:
    """Encrypt data using AES-256-GCM."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("Cryptography library not installed.")
    salt = os.urandom(SALT_SIZE)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(NONCE_SIZE)
    ciphertext = aesgcm.encrypt(nonce, data, None)
    return salt + nonce + ciphertext


def decrypt_data(encrypted_data: bytes, password: str) -> bytes:
    """Decrypt AES-256-GCM encrypted data."""
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("Cryptography library not installed.")
    salt = encrypted_data[:SALT_SIZE]
    nonce = encrypted_data[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_data[SALT_SIZE + NONCE_SIZE :]
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)


# --- Core Logic Class ---


class ZstdToolbox:
    """Encapsulates all functionality for the Zstandard toolbox."""

    def __init__(self):
        self.console = Console()

    def _create_progress_bar(self) -> Progress:
        """Create a standardized rich progress bar."""
        return Progress(
            TextColumn("[bold blue]{task.description}", justify="right"),
            BarColumn(bar_width=None),
            "[progress.percentage]{task.percentage:>3.1f}%",
            "•",
            FileSizeColumn(),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeRemainingColumn(),
            console=self.console,
        )

    def _prompt_for_path(
        self, prompt_text: str, must_exist=True, is_file=False, is_dir=False
    ) -> Path | None:
        """Handle path input and validation uniformly."""
        try:
            path_str = Prompt.ask(f"[cyan]{prompt_text}[/cyan]").strip('"')
            path = Path(path_str).resolve()
            if must_exist and not path.exists():
                self.console.print(
                    f"\n[bold red]错误: 路径 '{path}' 不存在！[/bold red]"
                )
                return None
            if is_file and not path.is_file():
                self.console.print(
                    f"\n[bold red]错误: 路径 '{path}' 不是一个文件！[/bold red]"
                )
                return None
            if is_dir and not path.is_dir():
                self.console.print(
                    f"\n[bold red]错误: 路径 '{path}' 不是一个目录！[/bold red]"
                )
                return None
            return path
        except Exception as e:
            self.console.print(f"\n[bold red]路径输入错误: {e}[/bold red]")
            return None

    def _stream_processor(
        self,
        in_fh: IO[bytes],
        out_fh: IO[bytes],
        processor: Callable,
        total_size: int,
        desc: str,
    ):
        """Generic stream processing engine with progress bar."""
        with self._create_progress_bar() as progress:
            task = progress.add_task(desc, total=total_size)
            with processor(out_fh) as stream:
                while chunk := in_fh.read(CHUNK_SIZE):
                    stream.write(chunk)
                    progress.update(task, advance=len(chunk))

    @contextmanager
    def _get_tar_source_stream(
        self, dir_path: Path, progress: Progress
    ) -> Generator[IO[bytes], Any, Any]:
        """Context manager to create a tar stream from a directory for piping."""
        self.console.print("扫描目录以计算总大小...")
        file_paths = [p for p in dir_path.rglob("*") if p.is_file()]
        total_size = sum(p.stat().st_size for p in file_paths)

        # This pipe allows tar to write to one end, and we read from the other, streaming.
        read_fd, write_fd = os.pipe()

        # The tar process will run in the background implicitly.
        # Once we start reading from read_fh, tarfile will start writing to write_fh.
        read_fh = os.fdopen(read_fd, "rb")
        write_fh = os.fdopen(write_fd, "wb")

        task = progress.add_task("打包中", total=total_size)

        try:
            with tarfile.open(fileobj=write_fh, mode="w|") as tar:
                # This context manager now yields the readable end of the pipe
                yield read_fh
                # This part will execute after the 'with' block using this manager finishes
                for p in file_paths:
                    arcname = p.relative_to(dir_path)
                    tar.add(str(p), arcname=str(arcname))
                    progress.update(task, advance=p.stat().st_size)
        finally:
            # Crucial: close the write end to signal EOF to the reader.
            write_fh.close()
            read_fh.close()  # Clean up the read end as well.

    def compress(self):
        self.console.print(Rule("[bold green]智能压缩 [文件/文件夹][/bold green]"))
        in_path = self._prompt_for_path("请输入要压缩的文件或文件夹路径")
        if not in_path:
            return

        level = IntPrompt.ask("请输入压缩级别 (1-22)", default=3, show_default=True)

        password = self._ask_for_password(encrypt=True) if CRYPTO_AVAILABLE else None

        suffix = ".tar.zst" if in_path.is_dir() else in_path.suffix + ".zst"
        if password:
            suffix += ".enc"
        out_path = in_path.with_suffix(suffix)

        self.console.print(
            f"\n处理中: [yellow]'{in_path.name}'[/yellow] -> [yellow]'{out_path.name}'[/yellow]..."
        )

        cctx = zstd.ZstdCompressor(level=level, threads=-1)

        try:
            if in_path.is_dir():
                # For directories, we need to calculate total size first for progress bar
                file_paths = [p for p in in_path.rglob("*") if p.is_file()]
                total_size = sum(p.stat().st_size for p in file_paths)

                # The data must be compressed first, then encrypted. Streaming encryption is complex.
                # So we compress to a temp file if encryption is needed.
                if password:
                    temp_path = out_path.with_suffix(".tmp")
                    with temp_path.open(
                        "wb"
                    ) as f_out, self._create_progress_bar() as progress:
                        # We need a custom tar stream handler here
                        task = progress.add_task("压缩中", total=total_size)
                        with cctx.stream_writer(f_out) as compressor:
                            with tarfile.open(fileobj=compressor, mode="w|") as tar:
                                for p in file_paths:
                                    tar.add(str(p), arcname=str(p.relative_to(in_path)))
                                    progress.update(task, advance=p.stat().st_size)

                    self.console.print("加密中...")
                    final_data = encrypt_data(temp_path.read_bytes(), password)
                    out_path.write_bytes(final_data)
                    temp_path.unlink()
                else:
                    # Stream directly if no encryption
                    with out_path.open(
                        "wb"
                    ) as f_out, self._create_progress_bar() as progress:
                        task = progress.add_task("压缩中", total=total_size)
                        with cctx.stream_writer(f_out) as compressor:
                            with tarfile.open(fileobj=compressor, mode="w|") as tar:
                                for p in file_paths:
                                    tar.add(str(p), arcname=str(p.relative_to(in_path)))
                                    progress.update(task, advance=p.stat().st_size)
            else:  # It's a file
                total_size = in_path.stat().st_size
                if password:
                    compressed_data = cctx.compress(in_path.read_bytes())
                    final_data = encrypt_data(compressed_data, password)
                    out_path.write_bytes(final_data)
                else:
                    with in_path.open("rb") as f_in, out_path.open("wb") as f_out:
                        self._stream_processor(
                            f_in, f_out, cctx.stream_writer, total_size, "压缩中"
                        )

            self.console.print("\n[bold green]✓ 操作成功！[/bold green]")
            self._print_summary(total_size, out_path.stat().st_size)

        except Exception as e:
            self.console.print(f"\n[bold red]✗ 操作失败: {e}[/bold red]")
            if "out_path" in locals() and out_path.exists():
                out_path.unlink(missing_ok=True)
            if "temp_path" in locals() and temp_path.exists():
                temp_path.unlink(missing_ok=True)

    def decompress(self):
        self.console.print(
            Rule("[bold green]智能解压 [.zst / .tar.zst / .enc][/bold green]")
        )
        in_path = self._prompt_for_path("请输入要解压的文件路径", is_file=True)
        if not in_path:
            return

        is_encrypted = in_path.name.lower().endswith(".enc")
        password = None
        if is_encrypted:
            if not CRYPTO_AVAILABLE:
                self.console.print(
                    "[bold red]错误: 加密库 'cryptography' 未安装，无法解密。[/bold red]"
                )
                return
            password = self._ask_for_password(encrypt=False)

        is_tar = ".tar.zst" in in_path.name.lower()

        out_name = Path(in_path.name.removesuffix(".enc"))
        out_path = Path(str(out_name).removesuffix(".zst").removesuffix(".tar"))
        if is_tar:
            out_path = Path(f"{out_path}_解压后")

        self.console.print(
            f"\n处理中: [yellow]'{in_path.name}'[/yellow] -> [yellow]'{out_path.name}'[/yellow]..."
        )

        try:
            dctx = zstd.ZstdDecompressor()
            in_data = in_path.read_bytes()
            if password:
                self.console.print("解密中...")
                in_data = decrypt_data(in_data, password)

            total_size = len(in_data)

            with self._create_progress_bar() as progress:
                task = progress.add_task("解压中", total=total_size)
                if is_tar:
                    out_path.mkdir(exist_ok=True)
                    with dctx.stream_reader(in_data) as reader:
                        with tarfile.open(fileobj=reader, mode="r|*") as tar:
                            # We cannot easily track tar extraction progress file by file without complexity
                            tar.extractall(path=out_path)
                            progress.update(
                                task, completed=total_size
                            )  # Mark as complete
                else:
                    with out_path.open("wb") as f_out:
                        f_out.write(dctx.decompress(in_data))
                        progress.update(task, completed=total_size)

            self.console.print("\n[bold green]✓ 操作成功！[/bold green]")
        except InvalidTag:
            self.console.print(
                "\n[bold red]✗ 解密失败！密码错误或文件已损坏。[/bold red]"
            )
        except zstd.ZstdError as e:
            self.console.print(
                f"\n[bold red]✗ 解压失败: Zstandard 错误 - {e}[/bold red]"
            )
        except Exception as e:
            self.console.print(f"\n[bold red]✗ 操作失败: {e}[/bold red]")

    def test_archive(self):
        self.console.print(Rule("[bold green]测试压缩文件完整性[/bold green]"))
        in_path = self._prompt_for_path("请输入要测试的 .zst 文件路径", is_file=True)
        if not in_path or self._check_if_encrypted(in_path):
            return

        self.console.print(f"\n正在测试文件: [yellow]{in_path}[/yellow]...")
        dctx = zstd.ZstdDecompressor()

        try:
            with in_path.open("rb") as f_in, open(os.devnull, "wb") as f_out:
                self._stream_processor(
                    f_in, f_out, dctx.stream_writer, in_path.stat().st_size, "测试中"
                )
            self.console.print(
                "[bold green]✓ 测试结果: 文件完整，没有错误。[/bold green]"
            )
        except zstd.ZstdError as e:
            self.console.print(
                f"[bold red]✗ 测试结果: 文件已损坏! 错误: {e}[/bold red]"
            )
        except Exception as e:
            self.console.print(f"[bold red]✗ 测试期间发生未知错误: {e}[/bold red]")

    def _ask_for_password(self, encrypt: bool) -> str | None:
        prompt_text = "加密" if encrypt else "解密"
        if not Confirm.ask(
            f"\n[bold yellow]是否需要{prompt_text}？[/bold yellow]",
            default=False if encrypt else True,
        ):
            return None
        while True:
            p1 = Prompt.ask(f"[cyan]请输入{prompt_text}密码[/cyan]", password=True)
            if encrypt:
                p2 = Prompt.ask("[cyan]请再次输入密码确认[/cyan]", password=True)
                if p1 != p2:
                    self.console.print(
                        "[bold red]错误: 两次输入的密码不匹配，请重试。[/bold red]"
                    )
                    continue
            if not p1:
                self.console.print("[bold red]错误: 密码不能为空。[/bold red]")
                continue
            return p1

    def _check_if_encrypted(self, path: Path) -> bool:
        if path.name.lower().endswith(".enc"):
            self.console.print(
                f"\n[bold yellow]提示:[/bold yellow] 此功能无法直接操作加密文件 [cyan]{path.name}[/cyan]。\n请先使用“解压”功能对其进行解密。"
            )
            return True
        return False

    def _print_summary(self, original_size: int, compressed_size: int):
        if original_size <= 0:
            return
        table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2), expand=False)
        table.add_column(style="cyan", justify="right")
        table.add_column(style="magenta")
        table.add_row("原始大小", f"{original_size:,} B")
        table.add_row("处理后大小", f"{compressed_size:,} B")
        ratio = compressed_size / original_size
        table.add_row("压缩率", f"{1/ratio:.2f}x ({ratio:.2%})")
        self.console.print(
            Panel(table, title="[bold]处理摘要[/bold]", border_style="green")
        )


def main_menu():
    """Displays the main menu and handles user choices."""
    toolbox = ZstdToolbox()
    actions = {
        "1": ("压缩文件或文件夹 (可选加密)", toolbox.compress),
        "2": ("解压文件或归档 (自动解密)", toolbox.decompress),
        "3": ("测试压缩文件 (不支持加密文件)", toolbox.test_archive),
        "4": ("退出", lambda: None),
    }

    while True:
        toolbox.console.clear()
        if sys.platform == "win32":
            os.system(f"title {TITLE}")

        panel_content = f"[bold yellow]{TITLE}[/bold yellow]\n\n[dim]一个高性能、高内存效率的压缩工具\n操作提示: 可直接将文件/文件夹拖拽到窗口输入路径[/dim]"
        if not CRYPTO_AVAILABLE:
            panel_content += "\n\n[bold red]警告:[/bold red] [i]cryptography[/i] 库未安装，加密/解密功能不可用。\n请运行: [cyan]pip install cryptography[/cyan]"

        toolbox.console.print(Panel(panel_content, border_style="green"))

        menu_table = Table.grid(padding=(0, 2))
        for key, (desc, _) in actions.items():
            menu_table.add_row(f"[bold cyan]{key}[/bold cyan].", desc)
        toolbox.console.print(menu_table)
        toolbox.console.print(Rule())

        choice = Prompt.ask("\n请输入您的选择", choices=actions.keys())
        _, action_func = actions[choice]

        if action_func is None:  # Exit condition
            toolbox.console.print("[bold magenta]感谢使用，再见！[/bold magenta]")
            break

        action_func()
        Prompt.ask("\n[dim]按 Enter 键返回主菜单...[/dim]")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        print("\n\n[bold yellow]操作被用户中断。正在退出...[/bold yellow]")
    except Exception as e:
        Console().print(f"[bold red]发生致命错误: {e}[/bold red]")
        Console().print_exception(show_locals=True)
