"""
Author: Fauzaan Gasim

OriginH is an encryption + hiding files tool.
The name is inspired by Charles Buttowski's Father whose code name is ORION.

This tool will implement an encryption that is impossible to break inspired by the bitcoin secret key design
"""
import os
import sys
import argparse
import hashlib
from PIL import Image
import numpy as np
import math
from pathlib import Path
from ecdsa import SigningKey, SECP256k1
import base58
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

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
    
    def _generate_default_container(self, index=None):
        """Generate a default container image"""
        # Create a random noise image
        img_size = (800, 600)
        random_array = np.random.randint(0, 255, (*img_size, 3), dtype=np.uint8)
        img = Image.fromarray(random_array)
        
        # Save to a temporary file
        container_path = f'container_{index}.png' if index is not None else 'container.png'
        img.save(container_path)
        return container_path

    def _split_data(self, data, max_size=5*1024*1024):  # 5MB chunks
        """Split data into chunks of maximum size"""
        return [data[i:i + max_size] for i in range(0, len(data), max_size)]

    def hide_file(self, source_path, container_path=None):
        """Hide encrypted file data inside another file, splitting if necessary"""
        encrypted_data = self.encrypt_file(source_path)
        chunks = self._split_data(encrypted_data)
        total_chunks = len(chunks)
        
        container_paths = []
        for i, chunk in enumerate(chunks):
            # Generate or use container path
            if container_path is None:
                current_container = self._generate_default_container(i if total_chunks > 1 else None)
                print(f"Generated container image {i+1}/{total_chunks}: {current_container}")
            else:
                base, ext = os.path.splitext(container_path)
                current_container = f"{base}_{i}{ext}" if total_chunks > 1 else container_path
            
            container_paths.append(current_container)
            
            # Write chunk with metadata
            with open(current_container, 'ab') as container:
                container.write(b'\n###ORION###\n')
                # Add chunk metadata and keys
                metadata = f"{i+1}/{total_chunks}".encode()
                key_data = self.private_key.to_string() + self.public_key.to_string()
                container.write(b'###META###' + metadata + b'###KEYS###' + key_data + b'###DATA###')
                container.write(chunk)
        
        return container_paths
    
    def extract_file(self, container_path, output_path):
        """Extract and decrypt hidden file from one or more containers"""
        # Check if we have multiple containers
        base, ext = os.path.splitext(container_path)
        all_data = []
        chunk_count = 0
        total_chunks = None
        
        while True:
            try:
                current_path = f"{base}_{chunk_count}{ext}" if chunk_count > 0 else container_path
                if not os.path.exists(current_path):
                    if chunk_count == 0:
                        raise ValueError(f"Container file not found: {current_path}")
                    break
                
                with open(current_path, 'rb') as container:
                    content = container.read()
                
                if b'###ORION###' not in content:
                    raise ValueError(f"No hidden content found in {current_path}")
                
                # Extract chunk metadata, keys and data
                hidden_content = content.split(b'###ORION###')[1].strip()
                if b'###META###' in hidden_content:
                    meta_part, rest = hidden_content.split(b'###KEYS###')
                    key_data, data = rest.split(b'###DATA###')
                    chunk_info = meta_part.split(b'###META###')[1].decode()
                    current, total = map(int, chunk_info.split('/'))
                    total_chunks = total
                    
                    # Restore keys
                    key_length = len(key_data) // 2
                    self.private_key = SigningKey.from_string(key_data[:key_length], curve=SECP256k1)
                    self.public_key = self.private_key.get_verifying_key()
                    
                    all_data.append((current - 1, data))  # Store with index for proper ordering
                else:
                    # Single file case
                    all_data.append((0, hidden_content))
                    break
                
                chunk_count += 1
                
            except Exception as e:
                if chunk_count == 0:
                    raise e
                break
        
        # Combine and decrypt data
        if len(all_data) > 1:
            # Sort by chunk index and combine
            all_data.sort(key=lambda x: x[0])
            combined_data = b''.join(chunk[1] for chunk in all_data)
        else:
            combined_data = all_data[0][1]
        
        decrypted_data = self.decrypt_file(combined_data)
        
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
            
            container_paths = orion.hide_file(args.source, args.container)
            if len(container_paths) > 1:
                print(f"\nFile split and hidden across {len(container_paths)} containers:")
                for path in container_paths:
                    print(f"- {path}")
            else:
                print(f"\nFile hidden successfully in {container_paths[0]}")
            
        elif args.action == 'extract':
            if not args.container or not args.key:
                parser.error("extract action requires --container and --key arguments")
            
            # Extract original filename from metadata
            orion = OrionH(args.key)
            orion.generate_key()
            output_path = f"recovered_{os.path.basename(args.container)}"
            orion.extract_file(args.container, output_path)
            print(f"File extracted successfully to {output_path}")
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
