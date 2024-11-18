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
from safetensors import safe_open
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from ecdsa import SigningKey, SECP256k1


class OrionH:
    def __init__(self, encryption_key=None):
        self.private_key = None
        self.public_key = None
        self.encryption_key = encryption_key or base64.urlsafe_b64encode(os.urandom(32)).decode()

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
        """Hide encrypted file data in a safetensors file"""
        if not self.private_key:
            self.generate_key()

        encrypted_data = self.encrypt_file(source_path)
        
        # Create orion_output directory if it doesn't exist
        output_dir = Path('orion_output')
        output_dir.mkdir(exist_ok=True)
        
        if output_path is None:
            output_path = output_dir / f"{Path(source_path).stem}.safetensors"
        
        # Prepare metadata and data
        metadata = {
            "filename": os.path.basename(source_path),
            "private_key": self.private_key.to_string().hex()
        }
        
        # Create tensors dict with encrypted data
        tensors = {
            "encrypted_data": encrypted_data
        }
        
        # Save to safetensors file
        with safe_open(output_path, framework="pt", torch_dtype="float32", device="cpu") as f:
            f.save_tensor("encrypted_data", encrypted_data)
            # Save metadata in the header
            f.write_metadata(metadata)
        
        return output_path

    def extract_file(self, safetensors_path, output_path):
        """Extract and decrypt hidden file from safetensors file"""
        # Load the safetensors file
        with safe_open(safetensors_path, framework="pt") as f:
            encrypted_data = f.get_tensor("encrypted_data")
            metadata = f.metadata()
        
        # Restore private key and derive public key
        self.private_key = SigningKey.from_string(bytes.fromhex(metadata["private_key"]), curve=SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
        
        # Get encrypted data and decrypt
        encrypted_data = tensors["encrypted_data"]
        decrypted_data = self.decrypt_file(encrypted_data)
        
        # Write decrypted data to output file
        with open(output_path, 'wb') as output:
            output.write(decrypted_data)

def main():
    parser = argparse.ArgumentParser(description='OrionH - File encryption and hiding tool')
    parser.add_argument('action', choices=['hide', 'extract'], help='Action to perform')
    parser.add_argument('--source', help='Source file path')
    parser.add_argument('--container', help='Container file path')
    parser.add_argument('--key', help='Encryption key (required for extraction)')

    args = parser.parse_args()

    try:
        if args.action == 'hide':
            if not args.source:
                parser.error("hide action requires --source argument")

            orion = OrionH()
            orion.generate_key()
            print("\nIMPORTANT: Save this encryption key securely (e.g., in Bitwarden).")
            print("You will need it to decrypt your files later!")
            print(f"\nEncryption Key: {orion.encryption_key}\n")

            output_path = orion.hide_file(args.source, args.container)
            print(f"\nFile hidden successfully in {output_path}")

        elif args.action == 'extract':
            if not args.container or not args.key:
                parser.error("extract action requires --container and --key arguments")

            orion = OrionH(args.key)

            # Create orion_output directory if it doesn't exist
            output_dir = Path('orion_output')
            output_dir.mkdir(exist_ok=True)
            
            # Load metadata to get original filename
            with safe_open(args.container, framework="pt") as f:
                metadata = f.metadata()
            original_filename = metadata["filename"]
            output_path = output_dir / f"recovered_{original_filename}"
            orion.extract_file(args.container, output_path)
            print(f"File extracted successfully to {output_path}")

    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
