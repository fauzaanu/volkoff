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
        self, private_key: bytes, file_ext: str, file_data: bytes, chunk_size=64*1024*1024
    ) -> bytes:
        """Encrypt the entire container including metadata using chunked approach"""
        # First encrypt metadata with a single chunk
        metadata = private_key + b"|" + file_ext.encode() + b"|"
        metadata_nonce = os.urandom(12)
        encrypted_metadata = self.aesgcm.encrypt(metadata_nonce, metadata, None)

        # Write metadata length, nonce and encrypted metadata
        result = bytearray()
        metadata_size = len(encrypted_metadata).to_bytes(8, 'big')
        result.extend(metadata_size + metadata_nonce + encrypted_metadata)

        # Then encrypt file data in chunks
        total_data = len(file_data)
        offset = 0
        chunk_number = 0

        while offset < total_data:
            remaining = total_data - offset
            current_chunk_size = min(chunk_size, remaining)
            chunk = file_data[offset:offset + current_chunk_size]

            # Generate unique nonce for each chunk
            chunk_nonce = os.urandom(8) + chunk_number.to_bytes(4, 'big')
            encrypted_chunk = self.aesgcm.encrypt(chunk_nonce, chunk, None)

            # Store chunk size, nonce and encrypted data
            chunk_size_bytes = len(encrypted_chunk).to_bytes(8, 'big')
            result.extend(chunk_size_bytes + chunk_nonce + encrypted_chunk)

            offset += current_chunk_size
            chunk_number += 1

        return bytes(result)

    def decrypt_container(self, encrypted_container: bytes) -> tuple[bytes, str, bytes]:
        """Decrypt the container and return components using chunked approach"""
        try:
            offset = 0
            total_size = len(encrypted_container)

            # First read and decrypt metadata
            if offset + 8 > total_size:
                raise ValueError("Container is too small to contain metadata size")
            metadata_size = int.from_bytes(encrypted_container[offset:offset + 8], 'big')
            offset += 8

            if offset + 12 > total_size:
                raise ValueError("Container is too small to contain metadata nonce")
            metadata_nonce = encrypted_container[offset:offset + 12]
            offset += 12

            if offset + metadata_size > total_size:
                raise ValueError("Container is too small to contain metadata")
            encrypted_metadata = encrypted_container[offset:offset + metadata_size]
            offset += metadata_size

            decrypted_metadata = self.aesgcm.decrypt(metadata_nonce, encrypted_metadata, None)
            try:
                private_key, file_ext, _ = decrypted_metadata.split(b"|", 2)
            except ValueError:
                raise ValueError("Invalid metadata format")

            # Then decrypt file data chunks
            decrypted_data = bytearray()

            while offset < total_size:
                # Ensure we have enough data for the chunk header
                if offset + 8 > total_size:
                    raise ValueError("Incomplete chunk size header")
                chunk_size = int.from_bytes(encrypted_container[offset:offset + 8], 'big')
                offset += 8

                if offset + 12 > total_size:
                    raise ValueError("Incomplete chunk nonce")
                chunk_nonce = encrypted_container[offset:offset + 12]
                offset += 12

                if offset + chunk_size > total_size:
                    raise ValueError("Incomplete chunk data")
                encrypted_chunk = encrypted_container[offset:offset + chunk_size]
                decrypted_chunk = self.aesgcm.decrypt(chunk_nonce, encrypted_chunk, None)
                decrypted_data.extend(decrypted_chunk)

                offset += chunk_size

            return private_key, file_ext.decode(), bytes(decrypted_data)

        except ValueError as e:
            raise ValueError(f"Container decryption failed: {str(e)}")
        except Exception as e:
            raise ValueError(f"Unexpected error during decryption: {str(e)}")

    def encrypt_file(self, file_path, chunk_size=64*1024*1024):  # 64MB chunks
        """Encrypt a file using AES-GCM with streaming"""
        encrypted_data = bytearray()

        with open(file_path, "rb") as file:
            chunk_number = 0
            while True:
                chunk = file.read(chunk_size)
                if not chunk:
                    break

                # Generate unique nonce for each chunk using chunk number
                nonce = os.urandom(8) + chunk_number.to_bytes(4, 'big')

                # Encrypt chunk
                encrypted_chunk = self.aesgcm.encrypt(nonce, chunk, None)

                # Store chunk size, nonce and encrypted data
                chunk_size_bytes = len(encrypted_chunk).to_bytes(8, 'big')
                encrypted_data.extend(chunk_size_bytes + nonce + encrypted_chunk)

                chunk_number += 1

        return bytes(encrypted_data)

    def decrypt_file(self, encrypted_data):
        """Decrypt file using AES-GCM with streaming"""
        try:
            decrypted_data = bytearray()
            offset = 0

            while offset < len(encrypted_data):
                # Read chunk size
                chunk_size = int.from_bytes(encrypted_data[offset:offset + 8], 'big')
                offset += 8

                # Read nonce
                nonce = encrypted_data[offset:offset + 12]
                offset += 12

                # Read and decrypt chunk
                encrypted_chunk = encrypted_data[offset:offset + chunk_size]
                decrypted_chunk = self.aesgcm.decrypt(nonce, encrypted_chunk, None)
                decrypted_data.extend(decrypted_chunk)

                offset += chunk_size

            return bytes(decrypted_data)
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

            console.print("[italic cyan]'It's hard to say goodbye...' 👋[/]")
            time.sleep(1.5)
            return

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
