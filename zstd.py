# -*- coding: utf-8 -*-
"""
Z-Archive Nexus (Reforged)
=============================================================
A high-performance, secure, chunk-based streaming archiver.
Optimized by: Code Expert
Stack: Typer, Rich, Zstandard, Cryptography
"""

from __future__ import annotations

import io
import os
import struct
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import IO, BinaryIO, Optional, cast

import typer
import zstandard as zstd
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.filesize import decimal
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TransferSpeedColumn,
)
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.theme import Theme

# --- Configuration & Constants ---
APP_NAME = "Z-Archive Nexus"
VERSION = "2.0.1"
BUFFER_SIZE = 1 * 1024 * 1024  # 1MB I/O Buffer
CHUNK_SIZE = 64 * 1024  # 64KB Encryption Chunk
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32  # AES-256
PBKDF2_ITERATIONS = 600_000
MAGIC_HEADER = b"ZARCv2"  # Versioned Header

# --- UI Theme ---
theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "highlight": "bold magenta",
        "muted": "dim white",
        "panel.border": "blue",
    }
)
console = Console(theme=theme)
app = typer.Typer(help=f"{APP_NAME}: 极速安全压缩工具", add_completion=False)


# --- Cryptography Engine (Chunked GCM) ---


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key using PBKDF2HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


class ChunkedAESWriter(io.BufferedIOBase):
    """
    Encrypts data in 64KB chunks using AES-256-GCM.
    Format: [Size(4B)][Nonce(12B)][Ciphertext][Tag(16B)]
    """

    def __init__(self, underlying: BinaryIO, password: str):
        self.underlying = underlying
        self.salt = os.urandom(SALT_SIZE)
        self.key = derive_key(password, self.salt)
        self.aesgcm = AESGCM(self.key)

        # Write File Header
        self.underlying.write(MAGIC_HEADER)
        self.underlying.write(self.salt)

        self._buffer = bytearray()

    def writable(self) -> bool:
        return True

    def write(self, b: bytes) -> int:
        if not b:
            return 0
        
        # If internal buffer + new data < CHUNK_SIZE, just append
        if len(self._buffer) + len(b) < CHUNK_SIZE:
            self._buffer.extend(b)
            return len(b)
        
        # Fill the buffer to CHUNK_SIZE and flush
        needed = CHUNK_SIZE - len(self._buffer)
        self._buffer.extend(b[:needed])
        self._flush_chunk(self._buffer)
        self._buffer = bytearray()
        
        # Process remaining full chunks directly from b
        offset = needed
        while offset + CHUNK_SIZE <= len(b):
            # Slicing creates a copy, but it's limited to CHUNK_SIZE (64KB)
            # which is better than extending a huge bytearray.
            chunk = b[offset : offset + CHUNK_SIZE]
            self._flush_chunk(chunk)
            offset += CHUNK_SIZE
            
        # Buffer the remaining bytes
        if offset < len(b):
            self._buffer.extend(b[offset:])
            
        return len(b)

    def _flush_chunk(self, data: bytes):
        if not data:
            return
        nonce = os.urandom(NONCE_SIZE)
        # AESGCM.encrypt returns ciphertext + tag
        ciphertext = self.aesgcm.encrypt(nonce, data, None)
        # Write: Length (4B) + Nonce (12B) + Content
        length = len(ciphertext) + NONCE_SIZE
        self.underlying.write(struct.pack(">I", length))
        self.underlying.write(nonce)
        self.underlying.write(ciphertext)

    def close(self):
        if not self.closed:
            if self._buffer:
                self._flush_chunk(self._buffer)
            # Write a 0-length marker to indicate stream end
            self.underlying.write(struct.pack(">I", 0))
            self.underlying.flush()
            # We don't close the underlying stream here to allow chaining
            super().close()


class ChunkedAESReader(io.BufferedIOBase):
    """
    Decrypts ZARCv2 chunked streams. Verified block-by-block.
    """

    def __init__(self, underlying: BinaryIO, password: str):
        self.underlying = underlying

        # Verify Header
        magic = self.underlying.read(len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise ValueError(f"无效的文件头: 期望 {MAGIC_HEADER!r}, 实际 {magic!r}")

        salt = self.underlying.read(SALT_SIZE)
        key = derive_key(password, salt)
        self.aesgcm = AESGCM(key)

        self._internal_buffer = bytearray()
        self._eof = False

    def readable(self) -> bool:
        return True

    def read(self, size: int = -1) -> bytes:
        if size == -1:
            # Read until EOF
            while not self._eof:
                if not self._read_next_chunk():
                    break
            result = self._internal_buffer[:]
            self._internal_buffer = bytearray()
            return bytes(result)

        while len(self._internal_buffer) < size and not self._eof:
            if not self._read_next_chunk():
                break

        result = self._internal_buffer[:size]
        self._internal_buffer = self._internal_buffer[size:]
        return bytes(result)

    def _read_next_chunk(self) -> bool:
        """Reads one encrypted block, decrypts it, appends to buffer."""
        # Read Length Header (4 bytes)
        len_bytes = self.underlying.read(4)
        if not len_bytes or len(len_bytes) < 4:
            self._eof = True
            return False

        chunk_len = struct.unpack(">I", len_bytes)[0]
        if chunk_len == 0:
            self._eof = True
            return False

        # Read Block (Nonce + Ciphertext + Tag)
        block = self.underlying.read(chunk_len)
        if len(block) != chunk_len:
            raise ValueError("文件截断或损坏")

        nonce = block[:NONCE_SIZE]
        ciphertext = block[NONCE_SIZE:]

        try:
            plaintext = self.aesgcm.decrypt(nonce, ciphertext, None)
            self._internal_buffer.extend(plaintext)
            return True
        except InvalidTag:
            raise InvalidTag("数据块验证失败：密码错误或文件被篡改")


# --- Logic Layer ---


@dataclass
class JobStats:
    source_size: int = 0
    final_size: int = 0
    start_time: float = 0
    end_time: float = 0

    @property
    def duration(self) -> float:
        return self.end_time - self.start_time

    @property
    def ratio(self) -> float:
        return (self.final_size / self.source_size * 100) if self.source_size > 0 else 0


class ArchiveEngine:
    """Core processing engine ensuring resource safety."""

    def __init__(self, console_obj: Console):
        self.console = console_obj

    def _get_password(self, confirm: bool = False) -> Optional[str]:
        if confirm:
            if not Confirm.ask("[warning]是否启用加密保护？[/warning]", default=False):
                return None

        prompt_text = "请输入密码" if not confirm else "设置加密密码"
        while True:
            p1 = Prompt.ask(f"[bold]{prompt_text}[/bold]", password=True)
            if not p1:
                continue

            if confirm:
                p2 = Prompt.ask("[bold]再次确认密码[/bold]", password=True)
                if p1 != p2:
                    self.console.print("[error]❌ 两次输入的密码不一致[/error]")
                    continue
            return p1

    def _create_progress(self) -> Progress:
        return Progress(
            SpinnerColumn(style="bold magenta"),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(
                bar_width=None,
                style="dim white",
                complete_style="green",
                finished_style="bold green",
            ),
            "[progress.percentage]{task.percentage:>3.0f}%",
            "•",
            DownloadColumn(),
            "•",
            TransferSpeedColumn(),
            "•",
            TimeElapsedColumn(),
            console=self.console,
            expand=True,
        )

    def _show_summary(self, stats: JobStats, success: bool, path: Path):
        if not success:
            return

        table = Table(box=None, show_header=False)
        table.add_column("Key", style="dim cyan", justify="right")
        table.add_column("Value", style="bold white")

        table.add_row("耗时", f"{stats.duration:.2f}s")
        table.add_row("原始大小", decimal(stats.source_size))
        table.add_row("结果大小", decimal(stats.final_size))
        table.add_row("压缩率", f"{stats.ratio:.2f}%")

        p = Panel(
            table,
            title="[bold green]Success[/bold green]",
            subtitle=f"Saved: {path.name}",
            border_style="green",
        )
        self.console.print(p)

    def run_compress(self, source: Path, level: int):
        if not source.exists():
            self.console.print(f"[error]路径不存在: {source}[/error]")
            return

        # Prepare Inputs
        password = self._get_password(confirm=True)
        ext = ".tar.zst" if source.is_dir() else ".zst"
        if password:
            ext += ".enc"
        dest = source.with_suffix(ext)

        # Calculate Size
        total_size = 0
        if source.is_file():
            total_size = source.stat().st_size
        else:
            with self.console.status("[bold cyan]正在扫描文件结构...", spinner="dots"):
                total_size = sum(
                    f.stat().st_size for f in source.rglob("*") if f.is_file()
                )

        # UI Setup
        stats = JobStats(source_size=total_size, start_time=os.times().elapsed)
        mode_str = "🔒 加密压缩" if password else "📦 普通压缩"

        self.console.rule(f"[bold]{mode_str}[/bold]")
        self.console.print(
            f"[muted]源:[/muted] {source.name}  [muted]目标:[/muted] {dest.name}  [muted]等级:[/muted] {level}"
        )

        # Execution Pipeline
        progress = self._create_progress()
        task_id = progress.add_task("Processing", total=total_size)

        try:
            with progress:
                with open(dest, "wb") as f_out:
                    # 1. Encryption Layer (Optional)
                    output_stream: IO[bytes] = f_out
                    enc_wrapper: Optional[ChunkedAESWriter] = None
                    if password:
                        enc_wrapper = ChunkedAESWriter(f_out, password)
                        output_stream = cast(IO[bytes], enc_wrapper)

                    # 2. Compression Layer (Zstd)
                    cctx = zstd.ZstdCompressor(level=level, threads=-1)

                    # 3. Stream Setup
                    if source.is_file():
                        context_manager = cctx.stream_writer(output_stream, size=total_size)
                    else:
                        # Directory (Tar stream): Size unknown, do not pass size arg
                        context_manager = cctx.stream_writer(output_stream)
                        
                    with context_manager as zstd_writer:
                        if source.is_dir():
                            with tarfile.open(fileobj=zstd_writer, mode="w|") as tar:
                                for file_path in source.rglob("*"):
                                    if file_path.is_file():
                                        arcname = file_path.relative_to(source.parent)
                                        tar.add(file_path, arcname=arcname)
                                        progress.update(
                                            task_id, advance=file_path.stat().st_size
                                        )
                        else:
                            with open(source, "rb") as f_in:
                                while chunk := f_in.read(BUFFER_SIZE):
                                    zstd_writer.write(chunk)
                                    progress.update(task_id, advance=len(chunk))

                    # Explicit Close for EncWrapper to write Footer
                    if enc_wrapper:
                        enc_wrapper.close()

            stats.end_time = os.times().elapsed
            stats.final_size = dest.stat().st_size
            self._show_summary(stats, success=True, path=dest)

        except Exception as e:
            dest.unlink(missing_ok=True)
            self.console.print(f"\n[error]💥 任务失败: {str(e)}[/error]")

    def run_decompress(self, source: Path):
        if not source.exists():
            self.console.print(f"[error]文件不存在: {source}[/error]")
            return

        # Name Deduction
        clean_name = source.name.replace(".enc", "").replace(".zst", "")
        dest_path = source.parent / clean_name.replace(".tar", "")
        is_tar = ".tar" in str(source) or source.name.endswith(".tar.zst") or source.name.endswith(".tar.zst.enc")
        
        # Adjust dest_path for tar extraction
        if is_tar:
            dest_path = source.parent / (dest_path.name + "_extracted")

        file_size = source.stat().st_size
        stats = JobStats(source_size=file_size, start_time=os.times().elapsed)

        self.console.rule("[bold]🔓 解压/解密[/bold]")
        self.console.print(
            f"[muted]源:[/muted] {source.name}  [muted]输出:[/muted] {dest_path.name}"
        )

        progress = self._create_progress()
        task_id = progress.add_task("Decrypting & Unpacking", total=file_size)

        try:
            with progress:
                with open(source, "rb") as f_raw:
                    # 1. Detect Encryption via Header
                    header = f_raw.read(len(MAGIC_HEADER))
                    f_raw.seek(0)
                    is_encrypted = (header == MAGIC_HEADER)
                    
                    password = None
                    if is_encrypted:
                        # Pause progress to ask for password if needed (though CLI usually asks before progress starts)
                        # Since we are inside progress context, printing might break the bar momentarily.
                        # Ideally we ask before, but we didn't know it was encrypted.
                        # Rich handles print/input inside progress somewhat, but it's cleaner to ask.
                        progress.stop()
                        self.console.print("[info]检测到加密文件头[/info]")
                        password = self._get_password(confirm=False)
                        progress.start()

                    # 2. Progress Wrapper
                    class ProgressReader:
                        def __init__(self, stream: BinaryIO):
                            self._stream = stream

                        def read(self, size: int = -1) -> bytes:
                            data = self._stream.read(size)
                            if data:
                                progress.update(task_id, advance=len(data))
                            return data

                        def seek(self, offset: int, whence: int = 0) -> int:
                            return self._stream.seek(offset, whence)
                            
                        def tell(self) -> int:
                            return self._stream.tell()

                        def readable(self) -> bool:
                            return True

                    monitored_stream = cast(BinaryIO, ProgressReader(f_raw))

                    # 3. Decryption Layer
                    input_stream: IO[bytes] = monitored_stream
                    if is_encrypted:
                        if not password:
                             # Should have been asked above
                             raise ValueError("加密文件需要密码")
                        input_stream = cast(IO[bytes], ChunkedAESReader(monitored_stream, password))

                    # 4. Decompression & Extraction
                    dctx = zstd.ZstdDecompressor()

                    if is_tar:
                        dest_path.mkdir(parents=True, exist_ok=True)
                        with dctx.stream_reader(input_stream) as zstd_reader:
                            # Tarfile stream read
                            with tarfile.open(fileobj=zstd_reader, mode="r|") as tar:
                                tar.extractall(path=dest_path)
                    else:
                        with open(dest_path, "wb") as f_out:
                            dctx.copy_stream(
                                input_stream,
                                f_out,
                                read_size=BUFFER_SIZE,
                                write_size=BUFFER_SIZE,
                            )

            stats.end_time = os.times().elapsed
            self.console.print(
                Panel(
                    f"[bold green]✔ 操作成功完成[/bold green]\n保存至: [underline]{dest_path}[/underline]",
                    border_style="green",
                )
            )

        except InvalidTag:
            self.console.print(
                "\n[error]⛔ 完整性校验失败: 密码错误或数据块被篡改。[/error]"
            )
        except Exception as e:
            self.console.print(f"\n[error]💥 错误: {str(e)}[/error]")


# --- CLI Commands ---

engine = ArchiveEngine(console)


@app.command(name="compress")
def cli_compress(
    path: Path = typer.Argument(..., help="Source file or directory", exists=True),
    level: int = typer.Option(
        3, "--level", "-l", min=1, max=22, help="Compression level (1-22)"
    ),
):
    """Create a secure Zstandard archive."""
    engine.run_compress(path, level)


@app.command(name="extract")
def cli_extract(
    path: Path = typer.Argument(
        ..., help="Archive file (.zst, .enc)", exists=True, dir_okay=False
    )
):
    """Decompress and decrypt an archive."""
    engine.run_decompress(path)


@app.command()
def ui():
    """Launch the interactive TUI menu."""
    while True:
        console.clear()

        # Header
        console.print(
            Panel.fit(
                f"[bold blue]{APP_NAME}[/bold blue] [dim]v{VERSION}[/dim]\n"
                "[italic cyan]Next-Gen Secure Storage[/italic cyan]",
                border_style="blue",
                padding=(1, 4),
            )
        )

        # Menu
        console.print("[bold white]1.[/bold white] 压缩文件/文件夹")
        console.print("[bold white]2.[/bold white] 解压/还原")
        console.print("[bold white]q.[/bold white] 退出")
        console.print("")

        choice = Prompt.ask("选择操作", choices=["1", "2", "q"], default="1")

        if choice == "q":
            console.print("[heading]Goodbye![/heading]")
            break

        target_path_str = Prompt.ask("输入路径").strip('"').strip("'")
        if not target_path_str:
            continue
        target_path = Path(target_path_str)

        if choice == "1":
            level = IntPrompt.ask("压缩等级 (1-22)", default=3)
            engine.run_compress(target_path, level)
        elif choice == "2":
            engine.run_decompress(target_path)

        Prompt.ask("\n[dim]按回车键继续...[/dim]", show_default=False)


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    Z-Archive Nexus: 极速安全压缩工具
    Run without arguments to start the Interactive UI.
    """
    if ctx.invoked_subcommand is None:
        ui()


if __name__ == "__main__":
    app()
