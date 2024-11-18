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
    
    def hide_file(self, source_path, container_path):
        """Hide encrypted file data inside another file"""
        encrypted_data = self.encrypt_file(source_path)
        
        with open(container_path, 'ab') as container:
            container.write(b'\n###ORION###\n')
            container.write(encrypted_data)
    
    def extract_file(self, container_path, output_path):
        """Extract and decrypt hidden file"""
        with open(container_path, 'rb') as container:
            content = container.read()
        
        if b'###ORION###' not in content:
            raise ValueError("No hidden content found")
            
        hidden_data = content.split(b'###ORION###')[1].strip()
        decrypted_data = self.decrypt_file(hidden_data)
        
        with open(output_path, 'wb') as output:
            output.write(decrypted_data)

def main():
    parser = argparse.ArgumentParser(description='OrionH - File encryption and hiding tool')
    parser.add_argument('action', choices=['hide', 'extract'], help='Action to perform')
    parser.add_argument('--source', help='Source file path')
    parser.add_argument('--container', help='Container file path')
    parser.add_argument('--output', help='Output file path for extraction')
    parser.add_argument('--key', help='Encryption key (required for extraction)')
    
    args = parser.parse_args()
    
    try:
        if args.action == 'hide':
            if not args.source or not args.container:
                parser.error("hide action requires --source and --container arguments")
            
            orion = OrionH()
            orion.generate_key()
            print("\nIMPORTANT: Save this encryption key securely (e.g., in Bitwarden).")
            print("You will need it to decrypt your files later!")
            print(f"\nEncryption Key: {orion.encryption_key}\n")
            
            orion.hide_file(args.source, args.container)
            print(f"File hidden successfully in {args.container}")
            
        elif args.action == 'extract':
            if not args.container or not args.output or not args.key:
                parser.error("extract action requires --container, --output, and --key arguments")
            
            orion = OrionH(args.key)
            orion.generate_key()
            orion.extract_file(args.container, args.output)
            print(f"File extracted successfully to {args.output}")
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
