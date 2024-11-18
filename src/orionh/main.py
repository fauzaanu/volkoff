import base64
import time
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box
from rich.table import Table
import hashlib
import os
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ecdsa import SigningKey, SECP256k1

from orionh.tui import (
    list_current_files,
    create_menu,
    create_header,
    process_file,
    display_result,
)


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



def main():
    console = Console()

    import sys

    # Get input file from command line if provided
    input_file = sys.argv[1] if len(sys.argv) > 1 else None
    operation = True

    while operation:
        try:
            console.clear()
            console.print(create_header())
            console.print("\n" + create_menu())

            # If input file was provided via command line, automatically hide it
            if input_file:
                console.print(f"\n[bold cyan]Processing file:[/] {input_file}")
                file_path = input_file
                choice = "h"
            else:
                # Otherwise show menu and get user choice
                choice = Prompt.ask(
                    "\nEnter your choice", choices=["h", "d", "q"], default="q"
                ).lower()

                if choice == "q":
                    console.print("[yellow]Goodbye![/]")
                    return
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
                success, error_msg, output_path = process_file(
                    "extract", file_path, key
                )
                display_result(success, error_msg, output_path, console)

            Prompt.ask("\nIts Hard to say Goodbye. Press ENTER")
            operation = False
            sys.exit(0)

        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/]")
            time.sleep(1)
            sys.exit(0)
        except Exception as e:
            console.print(f"\n[bold red]An error occurred:[/] {str(e)}")
            time.sleep(2)
            sys.exit(0)

        except (KeyboardInterrupt, EOFError):
            Console().print("\n[yellow]Program terminated by user. Goodbye![/yellow]")
            sys.exit(0)


if __name__ == "__main__":
    # DO NOT MODIFY THIS PART
    main()
