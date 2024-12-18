import os

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
import time
from pathlib import Path


def create_header() -> str:
    """Create the application header"""

    env_present = True if os.getenv("VOLKOFF_KEY") else False

    message = (
        "\n[bold cyan]Volkoff[/]\n"
        "[yellow]Volkoff is a simple tool to encrypt and decrypt files[/]"
    )

    if env_present:
        message += f"\n[bold green]Encryption key is set from VOLKOFF_KEY: {os.getenv('VOLKOFF_KEY')}[/]"
    else:
        message += "\n[bold red]VOLKOFF_KEY environment variable is not present, a new key will be generated[/]"

    return message


def create_menu() -> str:
    """Create the main menu text"""
    return (
        "[bold white on blue]  h  [/] [cyan]🔒 Encrypt File[/]\n"
        "[bold white on blue]  d  [/] [cyan]🔓 Decrypt File[/]\n"
        "[bold white on blue]  z  [/] [cyan]📦 Encrypt Folder[/]\n"
        "\n[bold white on red]  q  [/] [cyan]🚪 Exit[/]\n"
    )


def list_current_files(current_dir: Path = Path(".")):
    """
    List all files and directories in the given directory

    Returns a tuple of (files, directories, current_path)
    """
    # Get all entries in the directory
    entries = list(current_dir.iterdir())

    # Separate files and directories
    files = [f for f in entries if f.is_file()]
    dirs = [d for d in entries if d.is_dir()]

    # Sort alphabetically
    files.sort()
    dirs.sort()

    return files, dirs, current_dir.resolve()


def format_directory_listing(
    files: list[Path], dirs: list[Path], current_path: Path
) -> str:
    """Format the directory listing with numbers and icons"""
    output = [f"\n📂 Current directory: {current_path}\n"]

    # Add parent directory option if not in root
    if current_path != current_path.root:
        output.append("  0   [blue]...[/] (Parent directory)")

    # Add directories with folder emoji
    for i, dir_path in enumerate(dirs, start=1):
        output.append(f"  {i}   [blue]📁 {dir_path.name}[/]")

    # Add files with file emoji
    for i, file_path in enumerate(files, start=len(dirs) + 1):
        output.append(f"  {i}   📄 {file_path.name}")

    return "\n".join(output) if output else "\nNo files found in this directory"


def process_file(
    action: str, file_path: str | Path, key: str | None = None
) -> tuple[bool, str, Path | None]:
    """Process file with progress animation"""
    try:
        from .main import Volkoff

        # Validate encryption key for extract operation
        if action == "extract" and not key:
            return False, "Encryption key is required for extraction", None
        elif action == "extract" and len(key) < 32:
            return False, "Encryption key must be at least 32 characters long", None

        output_dir = Path("Volkoff")
        output_dir.mkdir(exist_ok=True)

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=Console(),
        ) as progress:
            if action == "hide":
                Volkoff = Volkoff()
                task = progress.add_task("[cyan]Encrypting...", total=100)
                for i in range(100):
                    progress.update(task, advance=1)
                    time.sleep(0.02)
                output_path = Volkoff.hide_file(file_path)
                return True, Volkoff.encryption_key, output_path

            else:  # extract
                if not key:
                    return False, "No encryption key provided", None

                Volkoff = Volkoff(key)
                task = progress.add_task("[cyan]Decrypting...", total=100)

                # Get original name without extension
                original_name = Path(file_path).stem
                temp_output_path = output_dir / original_name

                # Extract will handle decryption and return final path with proper extension
                output_path = Volkoff.extract_file(file_path, temp_output_path)

                for i in range(100):
                    progress.update(task, advance=1)
                    time.sleep(0.02)

                Volkoff.extract_file(file_path, output_path)
                return True, "", output_path

    except Exception as e:
        return False, str(e), None


def display_result(
    success: bool, message: str, output_path: Path | None, console: Console
) -> None:
    """Display the operation result"""
    if success:
        console.print("\n[bold green]✅ Success![/]")
        console.print(f"[blue]Output:[/] {output_path}")
        if message:
            console.print(f"[yellow]Key:[/] [bold red]{message}[/]")
    else:
        console.print(f"\n[bold red]❌ Error:[/] {message}")
        if "Incorrect decryption key" in message:
            console.print(
                "[yellow]Hint:[/] Make sure you're using the exact key that was provided during encryption"
            )
