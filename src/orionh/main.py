"""
Author: Fauzaan Gasim

OriginH is an encryption + hiding files tool.
The name is inspired by Charles Buttowski's Father whose code name is ORION.

This tool will implement an encryption that is impossible to break inspired by the bitcoin secret key design
"""

import base64
import time
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.layout import Layout
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.prompt import Prompt
from rich import box
from rich.align import Align
import hashlib
import os
import glob
from pathlib import Path

import base58
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ecdsa import SigningKey, SECP256k1


class OrionH:
    """
    OrionH class for file encryption and hiding

    Args:
        encryption_key (str, optional): The encryption key to use. If not provided,
            a new random key will be generated.
    """

    def __init__(self, encryption_key: str | None = None):
        if encryption_key:
            # For extraction: use provided key
            self.encryption_key = encryption_key
            key_bytes = hashlib.sha256(encryption_key.encode()).digest()
            self.private_key = SigningKey.from_string(key_bytes, curve=SECP256k1)
            self.public_key = self.private_key.get_verifying_key()
        else:
            # For hiding: generate new random key
            key_bytes = os.urandom(32)
            self.encryption_key = "".join(
                chr((b % 26) + 65) for b in key_bytes
            )  # Use only A-Z
            key_bytes = hashlib.sha256(self.encryption_key.encode()).digest()
            self.private_key = SigningKey.from_string(key_bytes, curve=SECP256k1)
            self.public_key = self.private_key.get_verifying_key()

    def generate_key(self):
        """Generate a Bitcoin-style private key using SECP256k1"""
        self.private_key = SigningKey.generate(curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
        return self.private_key.to_string().hex()

    def get_address(self):
        """Generate a Bitcoin-style address from the public key"""
        public_key_bytes = self.public_key.to_string()
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        ripemd160_hash = hashlib.new("ripemd160", sha256_hash).digest()

        # Add version byte (0x00 for mainnet)
        version_ripemd160_hash = b"\x00" + ripemd160_hash

        # Double SHA256 for checksum
        double_sha256 = hashlib.sha256(
            hashlib.sha256(version_ripemd160_hash).digest()
        ).digest()
        checksum = double_sha256[:4]

        # Combine version, hash, and checksum
        binary_address = version_ripemd160_hash + checksum

        # Convert to Base58Check encoding
        address = base58.b58encode(binary_address).decode("utf-8")
        return address

    def _derive_key(self, salt=None):
        """Derive an encryption key using the stored encryption key"""
        if not self.encryption_key:
            raise ValueError("No encryption key set")

        if salt is None:
            salt = os.urandom(16)

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480000,
        )

        key = base64.urlsafe_b64encode(kdf.derive(self.encryption_key.encode()))
        return key, salt

    def encrypt_file(self, file_path):
        """Encrypt a file using AES and sign it with ECDSA"""
        if not self.private_key:
            raise ValueError("No private key set")

        with open(file_path, "rb") as file:
            file_data = file.read()

        # Generate encryption key and encrypt data
        key, salt = self._derive_key()
        f = Fernet(key)
        encrypted_data = f.encrypt(file_data)

        # Sign the encrypted data
        data_hash = hashlib.sha256(encrypted_data).digest()
        signature = self.private_key.sign(data_hash)

        # Combine encrypted data with salt and signature
        return encrypted_data + b"###SALT###" + salt + b"###SIG###" + signature

    def decrypt_file(self, encrypted_data):
        """Decrypt file and verify signature"""
        if not self.public_key:
            raise ValueError("No public key set")

        try:
            # Split components
            encrypted_content, rest = encrypted_data.split(b"###SALT###")
            salt, signature = rest.split(b"###SIG###")

            # Verify signature
            data_hash = hashlib.sha256(encrypted_content).digest()
            self.public_key.verify(signature, data_hash)

            # Decrypt data
            key, _ = self._derive_key(salt)
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_content)

            return decrypted_data
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def hide_file(
        self, source_path: str | Path, output_path: Path | None = None
    ) -> Path:
        from orionh.hide import hide_file

        return hide_file(self, source_path, output_path)

    def extract_file(self, safetensors_path: str | Path, output_path: Path) -> None:
        from orionh.extract import extract_file

        return extract_file(self, safetensors_path, output_path)


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


def process_file(
    action: str, file_path: str | Path, key: str | None = None
) -> tuple[bool, str, Path | None]:
    """Process file with progress animation"""
    try:
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


def list_current_files():
    """List all files in the current directory"""
    files = glob.glob("*")
    return [f for f in files if os.path.isfile(f)]


def main(input_file: str | None = None):
    console = Console()

    while True:
        try:
            console.clear()
            layout = Layout()
            
            # Show input file notification if one is provided
            if input_file:
                notification = Panel(
                    f"[bold cyan]Processing file:[/] {input_file}",
                    border_style="cyan"
                )
                layout.split_column(
                    Layout(create_header(), size=4),
                    Layout(notification, size=3),
                    Layout(create_menu(), size=6),
                )
                console.print(layout)
                # Automatically proceed with hiding for provided file
                choice = "h"
            else:
                layout.split_column(
                    Layout(create_header(), size=4),
                    Layout(create_menu(), size=6),
                )
                console.print(layout)
                # Get user choice only if no input file
                choice = Prompt.ask("\nEnter your choice", choices=["h", "d", "q"], default="q").lower()

            if choice == "q":
                console.print("[yellow]Goodbye![/]")
                return

            file_path = input_file
            if not file_path:
                files = list_current_files()
                if not files:
                    console.print(
                        Panel(
                            "[bold red]No files found in current directory![/]",
                            border_style="red",
                        )
                    )
                    time.sleep(2)
                    continue

                # Display file listing in a compact table
                file_table = Table(show_header=False, box=box.SIMPLE)
                file_table.add_column("Number", style="cyan")
                file_table.add_column("Filename")
                for i, file in enumerate(files, 1):
                    file_table.add_row(str(i), file)
                console.print("\nAvailable files:")
                console.print(file_table)

                # Get file selection
                try:
                    file_index = int(Prompt.ask("Enter file number", default="1"))
                    file_path = files[file_index - 1]
                    if not Path(file_path).exists():
                        raise ValueError("File not found!")
                except (IndexError, ValueError) as e:
                    console.print(Panel(f"[bold red]{str(e)}[/]", border_style="red"))
                    time.sleep(2)
                    continue

            if choice == "h":  # Hide
                success, key, output_path = process_file("hide", file_path)
                display_result(success, key, output_path, console)
            else:  # Decrypt/Extract
                key = Prompt.ask("Enter encryption key")
                success, error_msg, output_path = process_file("extract", file_path, key)
                display_result(success, error_msg, output_path, console)

            Prompt.ask("\nPress Enter to continue...")

        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/]")
            time.sleep(1)
            continue
        except Exception as e:
            console.print(f"\n[bold red]An error occurred:[/] {str(e)}")
            time.sleep(2)


if __name__ == "__main__":
    import sys
    try:
        input_file = sys.argv[1] if len(sys.argv) > 1 else None
        main(input_file)
    except (KeyboardInterrupt, EOFError):
        Console().print("\n[yellow]Program terminated by user. Goodbye![/yellow]")
    except Exception as e:
        Console().print(f"\n[bold red]Fatal error:[/] {str(e)}")
