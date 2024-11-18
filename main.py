"""
Author: Fauzaan Gasim

OriginH is an encryption + hiding files tool.
The name is inspired by Charles Buttowski's Father whose code name is ORION.

This tool will implement an encryption that is impossible to break inspired by the bitcoin secret key design
"""
import argparse
import base64
import hashlib
import os
import sys
from pathlib import Path

import base58
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ecdsa import SigningKey, SECP256k1


class OrionH:
    def __init__(self, encryption_key=None):
        if encryption_key:
            # For extraction: use provided key
            self.encryption_key = encryption_key
            key_bytes = hashlib.sha256(encryption_key.encode()).digest()
            self.private_key = SigningKey.from_string(key_bytes, curve=SECP256k1)
            self.public_key = self.private_key.get_verifying_key()
        else:
            # For hiding: generate new random key
            key_bytes = os.urandom(32)
            self.encryption_key = ''.join(chr((b % 26) + 65) for b in key_bytes)  # Use only A-Z
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
        ripemd160_hash = hashlib.new('ripemd160', sha256_hash).digest()

        # Add version byte (0x00 for mainnet)
        version_ripemd160_hash = b'\x00' + ripemd160_hash

        # Double SHA256 for checksum
        double_sha256 = hashlib.sha256(hashlib.sha256(version_ripemd160_hash).digest()).digest()
        checksum = double_sha256[:4]

        # Combine version, hash, and checksum
        binary_address = version_ripemd160_hash + checksum

        # Convert to Base58Check encoding
        address = base58.b58encode(binary_address).decode('utf-8')
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

        with open(file_path, 'rb') as file:
            file_data = file.read()

        # Generate encryption key and encrypt data
        key, salt = self._derive_key()
        f = Fernet(key)
        encrypted_data = f.encrypt(file_data)

        # Sign the encrypted data
        data_hash = hashlib.sha256(encrypted_data).digest()
        signature = self.private_key.sign(data_hash)

        # Combine encrypted data with salt and signature
        return encrypted_data + b'###SALT###' + salt + b'###SIG###' + signature

    def decrypt_file(self, encrypted_data):
        """Decrypt file and verify signature"""
        if not self.public_key:
            raise ValueError("No public key set")

        try:
            # Split components
            encrypted_content, rest = encrypted_data.split(b'###SALT###')
            salt, signature = rest.split(b'###SIG###')

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


    def hide_file(self, source_path, output_path=None):
        """Hide encrypted file data"""
        encrypted_data = self.encrypt_file(source_path)

        # Create orion_output directory if it doesn't exist
        output_dir = Path('orion_output')
        output_dir.mkdir(exist_ok=True)

        if output_path is None:
            output_path = output_dir / f"{Path(source_path).stem}.safetensors"

        # Create output directory if it doesn't exist
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Store private key and original extension with encrypted data
        private_key_hex = self.private_key.to_string().hex()
        original_ext = Path(source_path).suffix
        stored_data = f"{private_key_hex}###KEY###{original_ext}###EXT###".encode() + encrypted_data

        # Save to file
        with open(output_path, 'wb') as f:
            f.write(stored_data)

        return output_path

    def extract_file(self, safetensors_path, output_path):
        """Extract and decrypt hidden file"""
        # Load the stored data
        with open(safetensors_path, 'rb') as f:
            stored_data = f.read()

        # Split private key, extension and encrypted data
        stored_key, rest = stored_data.split(b'###KEY###', 1)
        original_ext, encrypted_data = rest.split(b'###EXT###', 1)
        stored_key = stored_key.decode()
        original_ext = original_ext.decode()

        # Verify the key matches
        if stored_key != self.private_key.to_string().hex():
            raise ValueError("Incorrect decryption key")

        # Decrypt the data
        decrypted_data = self.decrypt_file(encrypted_data)

        # Write decrypted data to output file
        with open(output_path, 'wb') as output:
            output.write(decrypted_data)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OrionH - File encryption and hiding tool')
    parser.add_argument('action', choices=['hide', 'extract'], help='Action to perform')
    parser.add_argument('input_file', help='Source file for hide, encrypted file for extract')
    parser.add_argument('key', nargs='?', help='Encryption key (required for extract)')

    args = parser.parse_args()

    # Create output directory
    output_dir = Path('orion_output')
    output_dir.mkdir(exist_ok=True)

    if args.action == 'hide':
        orion = OrionH()  # Will generate a random encryption key internally
        print("\nIMPORTANT: Save this encryption key securely (e.g., in Bitwarden).")
        print("You will need it to decrypt your files later!")
        print(f"\nEncryption Key: {orion.encryption_key}\n")

        output_path = orion.hide_file(args.input_file)
        print(f"\nFile hidden successfully in {output_path}")

    elif args.action == 'extract':
        if not args.key:
            parser.error("extract action requires an encryption key")
        orion = OrionH(args.key)
        # Get the original file extension from the safetensors filename
        # Remove .safetensors and get original name
        original_name = Path(args.input_file).stem
        output_path = output_dir / f"recovered_{original_name}{original_ext}"
        orion.extract_file(args.input_file, output_path)
        print(f"File extracted successfully to {output_path}")
