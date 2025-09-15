import os
import io
import sys
import time
import tarfile
import shutil
from pathlib import Path
import zstandard as zstd
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    Progress,
    BarColumn,
    TextColumn,
    TransferSpeedColumn,
    TimeRemainingColumn,
    FileSizeColumn,
)
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from rich.rule import Rule
from rich.filesize import decimal
from rich import box


TITLE = "Zstandard 智能工具箱 (v2.3-Rich)"
console = Console()


class ProgressReader:
    """包裹一个文件类对象，在其上调用 read() 时更新 rich.progress。"""

    def __init__(self, file_obj, progress, task_id):
        self._file = file_obj
        self._progress = progress
        self._task = task_id
        try:
            self.total = os.fstat(self._file.fileno()).st_size
        except (io.UnsupportedOperation, AttributeError):
            self.total = None

    def read(self, size=-1):
        chunk = self._file.read(size)
        if chunk:
            self._progress.update(self._task, advance=len(chunk))
        return chunk

    def __getattr__(self, name):
        """将其他方法调用（如 fileno, seek）代理到底层文件对象。"""
        return getattr(self._file, name)


def prompt_for_path(
    prompt_text: str, must_exist=True, is_file=False, is_dir=False
) -> Path | None:
    """统一处理路径输入和验证。"""
    try:
        path_str = Prompt.ask(f"[cyan]{prompt_text}[/cyan]").strip('"')
        path = Path(path_str)
        if must_exist and not path.exists():
            console.print(f"\n[bold red]错误: 路径 '{path}' 不存在！[/bold red]")
            return None
        if is_file and not path.is_file():
            console.print(f"\n[bold red]错误: 路径 '{path}' 不是一个文件！[/bold red]")
            return None
        if is_dir and not path.is_dir():
            console.print(f"\n[bold red]错误: 路径 '{path}' 不是一个目录！[/bold red]")
            return None
        return path
    except Exception as e:
        console.print(f"\n[bold red]路径输入错误: {e}[/bold red]")
        return None


def get_progress_bar() -> Progress:
    """返回一个标准化的 rich 进度条实例。"""
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
        console=console,
    )


def print_compression_summary(original_size: int, compressed_size: int):
    """打印一个格式精美的压缩摘要报告。"""
    if original_size <= 0:
        return

    table = Table(show_header=False, box=box.ROUNDED, padding=(0, 2))
    table.add_column(style="cyan", justify="right")
    table.add_column(style="magenta")

    table.add_row("原始大小", str(decimal(original_size)))
    table.add_row("压缩后大小", str(decimal(compressed_size)))

    ratio = compressed_size / original_size
    ratio_str = f"{1/ratio:.2f}x  ({ratio:.2%})"
    table.add_row("压缩率", ratio_str)

    console.print(
        Panel(table, title="[bold]压缩摘要[/bold]", border_style="green", expand=False)
    )


def compress():
    console.print(Rule("[bold green]智能压缩 [文件/文件夹][/bold green]"))
    input_path = prompt_for_path("请输入要压缩的文件或文件夹路径")
    if not input_path:
        return

    level = IntPrompt.ask("请输入压缩级别 (1-22)", default=3, show_default=True)
    cctx = zstd.ZstdCompressor(level=level, threads=-1)

    progress = get_progress_bar()

    with progress:
        if input_path.is_dir():
            output_file = input_path.with_suffix(".tar.zst")
            console.print(
                f"\n正在打包并压缩文件夹 [yellow]'{input_path.name}'[/yellow] 到 [yellow]'{output_file.name}'[/yellow]..."
            )

            task_scan = progress.add_task(
                "[magenta]扫描文件...", total=None, start=False
            )
            file_paths = [p for p in input_path.rglob("*") if p.is_file()]
            total_size = sum(p.stat().st_size for p in file_paths)
            progress.stop_task(task_scan)
            progress.remove_task(task_scan)

            task_id = progress.add_task("压缩中", total=total_size)
            try:
                with open(output_file, "wb") as f_out:
                    with cctx.stream_writer(f_out) as compressor:
                        with tarfile.open(fileobj=compressor, mode="w|") as tar:
                            for p in file_paths:
                                arcname = p.relative_to(input_path.parent)
                                tar.add(str(p), arcname=str(arcname))
                                progress.update(task_id, advance=p.stat().st_size)

                console.print("\n[bold green]✓ 操作成功！[/bold green]")
                if output_file.exists():
                    compressed_size = output_file.stat().st_size
                    print_compression_summary(total_size, compressed_size)

            except Exception:
                console.print_exception(show_locals=True)
                console.print("\n[bold red]✗ 压缩失败。[/bold red]")

        else:  # 是文件
            output_file = input_path.with_suffix(input_path.suffix + ".zst")
            console.print(
                f"\n正在压缩文件 [yellow]'{input_path.name}'[/yellow] 到 [yellow]'{output_file.name}'[/yellow]..."
            )
            total_size = input_path.stat().st_size
            task_id = progress.add_task("压缩中", total=total_size)
            try:
                with open(input_path, "rb") as f_in, open(output_file, "wb") as f_out:
                    reader = ProgressReader(f_in, progress, task_id)
                    cctx.copy_stream(reader, f_out)

                console.print("\n[bold green]✓ 操作成功！[/bold green]")
                if output_file.exists():
                    compressed_size = output_file.stat().st_size
                    print_compression_summary(total_size, compressed_size)

            except Exception:
                console.print_exception(show_locals=True)
                console.print("\n[bold red]✗ 压缩失败。[/bold red]")


def decompress():
    console.print(Rule("[bold green]智能解压 [.zst / .tar.zst][/bold green]"))
    input_file = prompt_for_path("请输入要解压的文件路径", is_file=True)
    if not input_file:
        return

    dctx = zstd.ZstdDecompressor()
    is_tar = input_file.name.lower().endswith(".tar.zst")
    output_name = input_file.with_suffix("").name if not is_tar else "解压后的文件夹"
    console.print(
        f"\n正在解压 [yellow]'{input_file.name}'[/yellow] 到 [yellow]'{output_name}'[/yellow]..."
    )

    progress = get_progress_bar()

    try:
        with open(input_file, "rb") as f_in:
            with progress:
                try:
                    params = zstd.get_frame_parameters(f_in.read(18))
                    total_size = (
                        params.content_size if params.content_size > 0 else None
                    )
                except zstd.ZstdError:
                    total_size = None
                f_in.seek(0)

                task_id = progress.add_task("解压中", total=total_size)

                if is_tar:
                    with dctx.stream_reader(f_in) as reader:
                        progress_reader = ProgressReader(reader, progress, task_id)
                        with tarfile.open(fileobj=progress_reader, mode="r|*") as tar:
                            tar.extractall()
                else:
                    output_file = input_file.with_suffix("")
                    with open(output_file, "wb") as f_out:
                        reader = ProgressReader(f_in, progress, task_id)
                        dctx.copy_stream(
                            reader, f_out, read_size=io.DEFAULT_BUFFER_SIZE
                        )

        if total_size is None:
            processed = progress.tasks[task_id].completed
            progress.update(task_id, total=processed)

        console.print("\n[bold green]✓ 操作成功！[/bold green]")

    except Exception:
        console.print_exception(show_locals=True)
        console.print("\n[bold red]✗ 解压失败。[/bold red]")


def test_archive():
    console.print(Rule("[bold green]测试压缩文件完整性[/bold green]"))
    input_file = prompt_for_path("请输入要测试的 .zst 文件路径", is_file=True)
    if not input_file:
        return

    console.print(f"\n正在测试文件: [yellow]{input_file}[/yellow]...")
    dctx = zstd.ZstdDecompressor()
    progress = get_progress_bar()

    try:
        with open(input_file, "rb") as f_in:
            with progress:
                task = progress.add_task("测试中", total=input_file.stat().st_size)
                reader = ProgressReader(f_in, progress, task)
                with open(os.devnull, "wb") as f_out:
                    dctx.copy_stream(reader, f_out)
        console.print("[bold green]✓ 测试结果: 文件完整，没有错误。[/bold green]")
    except zstd.ZstdError as e:
        console.print(f"[bold red]✗ 测试结果: 文件已损坏! 错误: {e}[/bold red]")
    except Exception:
        console.print_exception(show_locals=True)
        console.print("[bold red]✗ 测试期间发生未知错误。[/bold red]")


def list_info():
    console.print(Rule("[bold green]查看压缩文件信息[/bold green]"))
    input_file = prompt_for_path("请输入要查看的 .zst 文件路径", is_file=True)
    if not input_file:
        return

    try:
        with open(input_file, "rb") as fh:
            params = zstd.get_frame_parameters(fh.read(18))

        compressed_size = input_file.stat().st_size
        content_size = params.content_size

        table = Table(
            title=f"文件 '{input_file.name}' 的 Zstandard 信息",
            box=box.MINIMAL_HEAVY_HEAD,
        )
        table.add_column("属性", style="cyan")
        table.add_column("值", style="magenta")

        table.add_row("压缩后大小", str(decimal(compressed_size)))

        if content_size and content_size > 0:
            ratio = compressed_size / content_size
            table.add_row("解压后大小", str(decimal(content_size)))
            table.add_row("压缩率", f"{1/ratio:.2f}x  ({ratio:.2%})")
        else:
            table.add_row("解压后大小", "[yellow]未声明（流式帧）[/yellow]")
            table.add_row("压缩率", "[yellow]N/A[/yellow]")

        table.add_row("字典 ID", str(params.dict_id or "无"))

        console.print(table)

    except zstd.ZstdError as e:
        console.print(
            f"\n[bold red]无法分析文件: {e}. 可能不是一个有效的 ZSTD 文件。[/bold red]"
        )
    except Exception:
        console.print_exception(show_locals=True)


def real_benchmark():
    console.print(Rule("[bold green]真实文件压缩性能基准测试 (级别 1-19)[/bold green]"))
    input_path = prompt_for_path("请输入用于测试的文件路径", is_file=True)
    if not input_path:
        return

    original_size = input_path.stat().st_size
    console.print(
        f"\n测试目标: [yellow]{input_path.name}[/yellow] ({decimal(original_size)})"
    )
    console.print("测试将在所有核心上运行。请稍候...")

    table = Table(title="Zstandard 压缩性能")
    table.add_column("级别", justify="center")
    table.add_column("压缩率", justify="right")
    table.add_column("压缩后", justify="right")
    table.add_column("压缩速度", justify="right", style="green")

    try:
        with get_progress_bar() as progress:
            task = progress.add_task("测试进度", total=19)
            for level in range(1, 20):
                cctx = zstd.ZstdCompressor(level=level, threads=-1)

                t0 = time.perf_counter()

                compressed_buffer = io.BytesIO()
                try:
                    with open(input_path, "rb") as f_in:

                        with cctx.stream_writer(
                            compressed_buffer, closefd=False
                        ) as compressor:
                            shutil.copyfileobj(f_in, compressor)

                    compressed_data = compressed_buffer.getvalue()
                    compressed_size = len(compressed_data)
                finally:

                    compressed_buffer.close()

                duration = time.perf_counter() - t0

                speed = (original_size / duration) if duration > 0 else 0
                ratio = (compressed_size / original_size) if original_size > 0 else 0

                table.add_row(
                    str(level),
                    f"{ratio:.2%}",
                    str(decimal(compressed_size)),
                    f"{decimal(speed)}/s",
                )
                progress.update(task, advance=1)

        console.print(table)
        console.print(
            "\n[dim]提示: 更高压缩率的 --ultra 级别 (20-22) 因速度较慢未包含在此测试中。[/dim]"
        )

    except Exception:
        console.print_exception(show_locals=True)


def main_menu():
    actions = {
        "1": ("压缩文件或文件夹", compress),
        "2": ("解压文件或归档", decompress),
        "3": ("测试压缩文件", test_archive),
        "4": ("查看压缩文件信息", list_info),
        "5": ("真实文件压缩性能测试", real_benchmark),
        "6": ("退出", sys.exit),
    }

    while True:
        console.clear()
        if sys.platform == "win32":
            os.system(f"title {TITLE}")

        console.print(
            Panel(
                f"[bold yellow]{TITLE}[/bold yellow]\n\n"
                "[dim]这是一个完全独立的工具，内置 Zstandard 引擎\n"
                "操作提示: 可直接将文件/文件夹拖拽到窗口输入路径[/dim]",
                border_style="green",
            )
        )

        menu_table = Table.grid(padding=(0, 2))
        for key, (desc, _) in actions.items():
            menu_table.add_row(f"[bold cyan]{key}[/bold cyan].", desc)

        console.print(menu_table)
        console.print(Rule())

        choice = Prompt.ask("\n请输入您的选择", choices=actions.keys())

        desc, action_func = actions[choice]
        if action_func == sys.exit:
            console.print("[bold magenta]感谢使用，再见！[/bold magenta]")
            break

        action_func()
        Prompt.ask("\n[dim]按 Enter 键返回主菜单...[/dim]")


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n\n[bold yellow]操作被用户中断。正在退出...[/bold yellow]")
        sys.exit(0)
    except Exception:
        console.print_exception(show_locals=True)
