import os
import time
from pathlib import Path

from rich.console import Console
from rich.prompt import Prompt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from volkoff.utils import handle_files_folder, handle_folder
from .tui import (
    create_menu,
    create_header,
    process_file,
    display_result,
)


class Volkoff:
    """
    Volkoff class for file encryption and hiding using AES-GCM

    Args:
        encryption_key (str, optional): The 32-byte hex key to use. If not provided,
            a new random key will be generated.
    """

    def __init__(self, encryption_key: str | None = None):
        if encryption_key:
            # For extraction: use provided key
            try:
                self.key = bytes.fromhex(encryption_key)
                if len(self.key) != 32:
                    raise ValueError("Key must be 32 bytes (64 hex characters)")
            except ValueError as e:
                raise ValueError(f"Invalid key format: {str(e)}")
            self.aesgcm = AESGCM(self.key)
        else:
            # For hiding: generate new random keys
            self.key = os.urandom(32)  # Main encryption key

            if os.getenv("VOLKOFF_KEY"):
                self.encryption_key = os.getenv("VOLKOFF_KEY")
            else:
                self.encryption_key = self.key.hex()

            self.aesgcm = AESGCM(self.key)

    def encrypt_container(
        self, private_key: bytes, file_ext: str, file_data: bytes
    ) -> bytes:
        """Encrypt the entire container including metadata"""
        # Structure: [encrypted[private_key | ext | data]]
        container = private_key + b"|" + file_ext.encode() + b"|" + file_data
        nonce = os.urandom(12)
        encrypted_container = self.aesgcm.encrypt(nonce, container, None)
        return nonce + encrypted_container

    def decrypt_container(self, encrypted_container: bytes) -> tuple[bytes, str, bytes]:
        """Decrypt the container and return components"""
        nonce = encrypted_container[:12]
        ciphertext = encrypted_container[12:]

        try:
            decrypted = self.aesgcm.decrypt(nonce, ciphertext, None)
            private_key, file_ext, file_data = decrypted.split(b"|", 2)
            return private_key, file_ext.decode(), file_data
        except Exception as e:
            raise ValueError(f"Container decryption failed: {str(e)}")

    def encrypt_file(self, file_path):
        """Encrypt a file using AES-GCM"""
        with open(file_path, "rb") as file:
            file_data = file.read()

        # Generate nonce
        nonce = os.urandom(12)

        # Encrypt data with authenticated encryption
        encrypted_data = self.aesgcm.encrypt(nonce, file_data, None)

        # Combine nonce and encrypted data
        return nonce + encrypted_data

    def decrypt_file(self, encrypted_data):
        """Decrypt file using AES-GCM"""
        try:
            # Split nonce and ciphertext
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]

            # Decrypt and authenticate data
            decrypted_data = self.aesgcm.decrypt(nonce, ciphertext, None)

            return decrypted_data
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")

    def hide_file(
        self, source_path: str | Path, output_path: Path | None = None
    ) -> Path:
        from .hide import hide_file

        return hide_file(self, source_path, output_path)

    def extract_file(self, safetensors_path: str | Path, output_path: Path) -> None:
        from .extract import extract_file

        return extract_file(self, safetensors_path, output_path)


def main():
    console = Console()
    operation = True
    current_dir = Path(".")

    while operation:
        try:
            console.clear()
            console.print(create_header())
            console.print("\n" + create_menu())

            choice = Prompt.ask(
                "\nEnter your choice", choices=["h", "d", "q", "ch"], default="q"
            ).lower()

            if choice == "q":
                console.print("[yellow]Goodbye![/]")
                return

            if choice == "h":  # Hide
                file_path = handle_files_folder(console, current_dir)
                success, key, output_path = process_file("hide", file_path)
                display_result(success, key, output_path, console)

            elif choice == "d":  # Extract
                file_path = handle_files_folder(console, current_dir)
                key = Prompt.ask("Enter encryption key")
                success, error_msg, output_path = process_file(
                    "extract", file_path, key
                )
                display_result(success, error_msg, output_path, console)

            elif choice == "ch":  # Compress Folder and Hide
                file_path = handle_folder(console, current_dir)
                success, key, output_path = process_file("hide", file_path)
                display_result(success, key, output_path, console)

            Prompt.ask("\nIts hard to say Goodbye!")
            operation = False

        except KeyboardInterrupt:
            console.print("\n[yellow]Operation cancelled by user[/]")
            time.sleep(1)
            break

        except Exception as e:
            console.print(f"\n[bold red]An error occurred:[/] {str(e)}")
            time.sleep(2)
            break


if __name__ == "__main__":
    # DO NOT MODIFY THIS PART (For Aider)
    main()
