# -*- coding: utf-8 -*-
"""
Z-Archive Nexus
=============================================================
A next-gen, high-performance secure archiver.
Stack: Typer, Rich, Zstandard, Cryptography.
"""

from __future__ import annotations

import io
import os
import sys
import tarfile
from pathlib import Path
from typing import IO, BinaryIO, Callable, Generator, Optional

import typer
import zstandard as zstd
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from rich.console import Console
from rich.filesize import decimal
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskID,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.text import Text
from rich.theme import Theme

# --- Configuration ---
BUFFER_SIZE = 4 * 1024 * 1024  # 4MB Buffer for High throughput
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
TAG_SIZE = 16
PBKDF2_ITERATIONS = 600_000  # Increased for better security
MAGIC_HEADER = b"ZARC"  # Custom header to verify file type

# --- Theme & UI ---
custom_theme = Theme(
    {
        "info": "cyan",
        "warning": "yellow",
        "error": "bold red",
        "success": "bold green",
        "heading": "bold blue",
    }
)
console = Console(theme=custom_theme)
app = typer.Typer(help="Z-Archive Nexus: 极速安全压缩工具", add_completion=False)

# --- Cryptography Layer (Stream Optimized) ---


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key using PBKDF2HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


class EncryptedStreamWriter(io.BufferedWriter):
    """Wraps a writable binary stream with AES-256-GCM encryption."""

    def __init__(self, underlying: BinaryIO, password: str):
        self.underlying = underlying
        self.salt = os.urandom(SALT_SIZE)
        self.nonce = os.urandom(NONCE_SIZE)
        key = derive_key(password, self.salt)

        # Write Header: Magic + Salt + Nonce
        self.underlying.write(MAGIC_HEADER)
        self.underlying.write(self.salt)
        self.underlying.write(self.nonce)

        cipher = Cipher(algorithms.AES(key), modes.GCM(self.nonce))
        self.encryptor = cipher.encryptor()
        super().__init__(self.underlying, buffer_size=BUFFER_SIZE)

    def write(self, b: bytes) -> int:
        # Encrypt data and write immediately
        ct = self.encryptor.update(b)
        if ct:
            self.underlying.write(ct)
        return len(b)

    def close(self):
        try:
            if not self.closed:
                self.flush()
                # Finalize encryption and write tag
                self.underlying.write(self.encryptor.finalize())
                self.underlying.write(self.encryptor.tag)
        finally:
            # Do not close underlying here to allow chaining logic outside
            pass


class DecryptedStreamReader(io.BufferedReader):
    """Wraps a readable binary stream with AES-256-GCM decryption."""

    def __init__(self, underlying: BinaryIO, password: str):
        self.underlying = underlying

        # Verify Header
        magic = self.underlying.read(len(MAGIC_HEADER))
        if magic != MAGIC_HEADER:
            raise ValueError("无效的文件格式或未加密的文件。")

        salt = self.underlying.read(SALT_SIZE)
        nonce = self.underlying.read(NONCE_SIZE)
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        self.decryptor = cipher.decryptor()

        # GCM requires the Tag to be at the end.
        # Since we are streaming, we can't verify the tag until the very end.
        # This is a limitation of streaming AEAD. We process optimistically.
        # However, standard GCM implementations in Python throw error only at finalize.

        self._buffer = bytearray()
        self._eof = False
        self._tag_buffer = bytearray()  # To hold the potential tag bytes

    def read(self, size: int = -1) -> bytes:
        # Simple block implementation: read larger chunk, decrypt, return
        # Note: This is a simplified streaming decryptor.
        # Ideally, we use a proper buffer window to separate ciphertext from tag.

        if size == -1:
            return self.readall()

        while len(self._buffer) < size and not self._eof:
            chunk = self.underlying.read(BUFFER_SIZE)
            if not chunk:
                self._eof = True
                self._finalize()
                break

            # Logic to separate Body from potential Tag at the end of stream
            # This logic is complex in streaming.
            # Simplified: We decrypt everything passed to update().
            # Cryptography lib handles buffering for GCM? No, it needs manual tag handling.

            # Strategy: We need to "peek" or ensure we don't decrypt the last 16 bytes
            # until we are sure it's the end.

            # Due to complexity of streaming GCM manually, we read standard chunks.
            # CAUTION: This specific implementation assumes the underlying stream ends cleanly.

            # Handling the "Tag is last 16 bytes" logic correctly:
            self._tag_buffer.extend(chunk)

            if len(self._tag_buffer) > TAG_SIZE:
                # Bytes safe to decrypt
                to_decrypt = self._tag_buffer[:-TAG_SIZE]
                self._tag_buffer = self._tag_buffer[-TAG_SIZE:]  # Keep last 16
                self._buffer.extend(self.decryptor.update(to_decrypt))

        result = self._buffer[:size]
        del self._buffer[:size]
        return bytes(result)

    def _finalize(self):
        # Now _tag_buffer contains the tag
        if len(self._tag_buffer) != TAG_SIZE:
            raise ValueError("文件截断，缺少校验标签。")

        try:
            # finalize_with_tag works if we passed the ciphertext via update() ??
            # No, finalize_with_tag expects the tag as argument,
            # and checks internal state against it.

            # Actually, cryptography's decryptor.finalize_with_tag(tag)
            # finishes the stream.
            self._buffer.extend(
                self.decryptor.finalize_with_tag(bytes(self._tag_buffer))
            )
        except InvalidTag:
            raise InvalidTag("密码错误或数据被篡改。")


# --- Progress Callback Wrapper ---


class ProgressFileObject(io.FileIO):
    """Proxy file object that updates a progress bar on read/write."""

    def __init__(self, path: str, mode: str, progress: Progress, task_id: TaskID):
        super().__init__(path, mode)
        self.progress = progress
        self.task_id = task_id

    def read(self, size: int = -1):
        data = super().read(size)
        self.progress.update(self.task_id, advance=len(data))
        return data

    def write(self, b):
        n = super().write(b)
        self.progress.update(self.task_id, advance=n)
        return n


# --- Core Logic ---


def get_password(is_encrypt: bool) -> Optional[str]:
    """Interactive password prompt."""
    if is_encrypt:
        if not Confirm.ask("[warning]是否加密文件？[/warning]", default=False):
            return None

    action = "加密" if is_encrypt else "解密"
    while True:
        p1 = Prompt.ask(f"[bold]请输入{action}密码[/bold]", password=True)
        if not p1:
            continue
        if is_encrypt:
            p2 = Prompt.ask("[bold]请再次输入确认[/bold]", password=True)
            if p1 != p2:
                console.print("[error]密码不匹配！[/error]")
                continue
        return p1


def compress_logic(source: Path, level: int):
    """Core compression pipeline."""
    if not source.exists():
        console.print(f"[error]路径不存在: {source}[/error]")
        return

    password = get_password(is_encrypt=True)

    # Determine Output Name
    ext = ".tar.zst" if source.is_dir() else ".zst"
    if password:
        ext += ".enc"
    dest = source.with_suffix(ext)

    # Setup Progress
    total_size = 0
    if source.is_file():
        total_size = source.stat().st_size
    else:
        console.print("[info]正在计算总大小...[/info]")
        total_size = sum(f.stat().st_size for f in source.rglob("*") if f.is_file())

    console.print(
        Panel(
            f"任务: [bold cyan]{source.name}[/bold cyan] -> [bold green]{dest.name}[/bold green]\n压缩等级: {level} | 加密: {'[green]开启[/green]' if password else '[dim]关闭[/dim]'}",
            title="Nexus Compressor",
        )
    )

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        "[progress.percentage]{task.percentage:>3.0f}%",
        DownloadColumn(),
        TransferSpeedColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:

        task = progress.add_task("Processing", total=total_size)

        try:
            # 1. Open Output File
            with open(dest, "wb") as f_out:
                # 2. Optional Encryption Layer
                stream_target = f_out
                enc_wrapper = None
                if password:
                    enc_wrapper = EncryptedStreamWriter(f_out, password)
                    stream_target = enc_wrapper

                # 3. Zstandard Compression Layer
                cctx = zstd.ZstdCompressor(level=level, threads=-1)
                with cctx.stream_writer(stream_target) as zstd_writer:

                    # 4. Data Source Layer
                    if source.is_dir():
                        # Tarball Stream
                        with tarfile.open(fileobj=zstd_writer, mode="w|") as tar:
                            for file_path in source.rglob("*"):
                                if file_path.is_file():
                                    arcname = file_path.relative_to(source.parent)
                                    tar.add(file_path, arcname=arcname)
                                    progress.update(
                                        task, advance=file_path.stat().st_size
                                    )
                    else:
                        # Single File Stream
                        with open(source, "rb") as f_in:
                            while chunk := f_in.read(BUFFER_SIZE):
                                zstd_writer.write(chunk)
                                progress.update(task, advance=len(chunk))

                # Flush encryption if active
                if enc_wrapper:
                    enc_wrapper.close()

            console.print(f"[success]✔ 成功保存至: {dest}[/success]")

            # Stats
            out_size = dest.stat().st_size
            ratio = (out_size / total_size) * 100 if total_size > 0 else 0
            console.print(
                f"[dim]原始: {decimal(total_size)} | 压缩后: {decimal(out_size)} | 压缩率: {ratio:.2f}%[/dim]"
            )

        except Exception as e:
            dest.unlink(missing_ok=True)
            console.print(f"[error]✘ 失败: {e}[/error]")
            # if debug: raise e


def decompress_logic(source: Path):
    """Core decompression pipeline."""
    if not source.exists():
        console.print(f"[error]文件不存在: {source}[/error]")
        return

    is_enc = source.name.endswith(".enc")
    password = None

    if is_enc:
        password = get_password(is_encrypt=False)

    # Determine Output Name
    stem = source.stem  # removes .enc if present, or .zst
    if is_enc:
        # source: data.tar.zst.enc -> stem: data.tar.zst
        # we need to strip .zst for the final logic check, but for now let's just look at name
        pass

    # Crude output name deduction
    out_str = str(source).replace(".enc", "").replace(".zst", "")
    is_tar = ".tar" in str(source)
    dest_path = Path(out_str.replace(".tar", ""))  # if tar, create folder

    if is_tar:
        dest_path = Path(str(dest_path) + "_extracted")

    console.print(
        Panel(
            f"任务: [bold cyan]{source.name}[/bold cyan] -> [bold green]{dest_path.name}[/bold green]",
            title="Nexus Decompressor",
        )
    )

    # We can't easily know total size of decompressed stream without reading headers or zstd frame content size
    # So we use file size as a proxy for "Read Progress"
    file_size = source.stat().st_size

    with Progress(
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        "[progress.percentage]{task.percentage:>3.0f}%",
        DownloadColumn(),
        TransferSpeedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Decrypting/Unpacking", total=file_size)

        try:
            with open(source, "rb") as f_in:
                # 1. Read Progress Wrapper
                # We wrap the raw file read to update progress bar
                def callback_reader(size):
                    data = f_in.read(size)
                    progress.update(task, advance=len(data))
                    return data

                # Hack: create an object that looks like file but calls callback
                # Or just update progress manually in the loop if not using tarfile
                # For tarfile, we need a file-like object.

                # 2. Decrypt Layer
                read_stream = f_in
                if is_enc:
                    # We need to read `f_in` via the wrapper logic?
                    # Actually DecryptedStreamReader calls f_in.read().
                    # We can wrap f_in with a progress updater before passing to Decryptor.
                    pass  # Progress update inside decryptor is hard due to buffering.
                    # Simple approach: update progress based on bytes read from `f_in`.
                    # Let's use the ProgressFileObject wrapper

                # Re-open with wrapper for progress
                pass

            # Re-implementation with cleaner stack
            with ProgressFileObject(
                str(source), "rb", progress, task
            ) as f_in_monitored:

                stream_src = f_in_monitored
                if password:
                    stream_src = DecryptedStreamReader(stream_src, password)

                dctx = zstd.ZstdDecompressor()

                if is_tar:
                    dest_path.mkdir(exist_ok=True)
                    with dctx.stream_reader(stream_src) as reader:
                        with tarfile.open(fileobj=reader, mode="r|") as tar:
                            tar.extractall(path=dest_path)
                else:
                    with open(dest_path, "wb") as f_out:
                        dctx.copy_stream(
                            stream_src,
                            f_out,
                            read_size=BUFFER_SIZE,
                            write_size=BUFFER_SIZE,
                        )

            console.print(f"[success]✔ 成功解压至: {dest_path}[/success]")

        except InvalidTag:
            console.print("[error]✘ 错误: 密码错误或文件已损坏 (MAC校验失败)。[/error]")
        except Exception as e:
            console.print(f"[error]✘ 失败: {e}[/error]")


# --- CLI Commands ---


@app.command()
def compress(
    path: Path = typer.Argument(..., help="输入文件或文件夹路径", exists=True),
    level: int = typer.Option(
        3, "--level", "-l", min=1, max=22, help="压缩等级 (1-22)"
    ),
):
    """压缩指定的文件或文件夹。"""
    compress_logic(path, level)


@app.command()
def extract(
    path: Path = typer.Argument(
        ..., help="输入 .zst 或 .enc 文件路径", exists=True, dir_okay=False
    ),
):
    """解压 .zst, .tar.zst 或 .enc 文件。"""
    decompress_logic(path)


@app.command()
def menu():
    """启动交互式主菜单。"""
    while True:
        console.clear()
        console.print(
            Panel(
                "[bold white]1.[/bold white] 压缩 (Compress)\n"
                "[bold white]2.[/bold white] 解压 (Extract)\n"
                "[bold white]3.[/bold white] 退出 (Exit)",
                title="[bold green]Z-Archive Nexus[/bold green]",
                subtitle="High-Performance Storage Tool",
                border_style="green",
            )
        )

        choice = Prompt.ask("请选择", choices=["1", "2", "3"], default="1")

        if choice == "3":
            console.print("[heading]Bye![/heading]")
            break

        path_str = Prompt.ask("请输入文件/文件夹路径").strip('"')
        path = Path(path_str)

        if choice == "1":
            if not path.exists():
                console.print("[error]路径不存在！[/error]")
                Prompt.ask("按回车继续...")
                continue
            lvl = IntPrompt.ask("压缩等级", default=3)
            compress_logic(path, lvl)
        elif choice == "2":
            if not path.exists() or not path.is_file():
                console.print("[error]文件不存在！[/error]")
                Prompt.ask("按回车继续...")
                continue
            decompress_logic(path)

        Prompt.ask("\n按回车返回菜单...")


@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """
    Nexus Archiver: 高性能压缩与加密工具。
    如果不带参数运行，将进入交互模式。
    """
    if ctx.invoked_subcommand is None:
        menu()


if __name__ == "__main__":
    app()
