from rich.panel import Panel
from rich.table import Table
from rich import box
import os
import glob



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
