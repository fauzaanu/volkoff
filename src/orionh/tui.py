from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.console import Console
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.align import Align
import os
import glob
import time
from pathlib import Path



def create_header() -> Panel:
    """Create the application header"""
    grid = Table.grid(expand=True)
    grid.add_column(justify="center", ratio=1)
    grid.add_row("[bold cyan]OrionH[/bold cyan]")
    grid.add_row("[yellow]Secure File Encryption & Hiding Tool[/yellow]")
    grid.add_row("[dim]Inspired by Charles Buttowski's Father - ORION[/dim]")
    return Panel(grid, box=box.DOUBLE)


def create_menu() -> Panel:
    """Create the main menu panel"""
    menu_items = [
        "[H] 🔒 Hide File",
        "[D] 🔓 Decrypt/Extract File",
        "[Q] 🚪 Quit",
    ]
    menu_text = "\n".join(menu_items)
    return Panel(menu_text, title="[b]Menu", border_style="green")


def list_current_files():
    """List all files in the current directory"""
    files = glob.glob("*")
    return [f for f in files if os.path.isfile(f)]


def process_file(
    action: str, file_path: str | Path, key: str | None = None
) -> tuple[bool, str, Path | None]:
    """Process file with progress animation"""
    try:
        from orionh.main import OrionH
        
        output_dir = Path("orion_output")
        output_dir.mkdir(exist_ok=True)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=Console(),
        ) as progress:
            if action == "hide":
                orion = OrionH()
                task = progress.add_task("[cyan]Encrypting...", total=100)
                for i in range(100):
                    progress.update(task, advance=1)
                    time.sleep(0.02)
                output_path = orion.hide_file(file_path)
                return True, orion.encryption_key, output_path

            else:  # extract
                if not key:
                    return False, "No encryption key provided", None

                orion = OrionH(key)
                task = progress.add_task("[cyan]Decrypting...", total=100)

                with open(file_path, "rb") as f:
                    stored_data = f.read()
                _, rest = stored_data.split(b"###KEY###", 1)
                original_ext, _ = rest.split(b"###EXT###", 1)
                original_ext = original_ext.decode()

                original_name = Path(file_path).stem
                output_path = output_dir / f"recovered_{original_name}{original_ext}"

                for i in range(100):
                    progress.update(task, advance=1)
                    time.sleep(0.02)

                orion.extract_file(file_path, output_path)
                return True, "", output_path

    except Exception as e:
        return False, str(e), None


def display_result(
    success: bool, message: str, output_path: Path | None, console: Console
) -> None:
    """Display the operation result"""
    if success:
        result_panel = Panel(
            Align.center(
                Text.from_markup(
                    f"[bold green]Operation Successful![/]\n\n"
                    f"[blue]Output:[/] {output_path}\n\n"
                    + (
                        f"[yellow]Encryption Key:[/] [bold red]{message}[/]\n"
                        if message
                        else ""
                    )
                )
            ),
            title="[bold green]✅ Success",
            border_style="green",
            box=box.DOUBLE,
        )
    else:
        result_panel = Panel(
            f"[bold red]Error:[/] {message}",
            title="[bold red]❌ Failed",
            border_style="red",
            box=box.DOUBLE,
        )
    console.print(result_panel)
