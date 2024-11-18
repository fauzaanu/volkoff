"""
Author: Fauzaan Gasim

OriginH is an encryption + hiding files tool.
The name is inspired by Charles Buttowski's Father whose code name is ORION.

This tool will implement an encryption that is impossible to break inspired by the bitcoin secret key design
"""
import os
import sys
import argparse
from cryptography.fernet import Fernet
from pathlib import Path

class OrionH:
    def __init__(self):
        self.key = None
        self.cipher_suite = None
        
    def generate_key(self):
        """Generate a new encryption key"""
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)
        return self.key
    
    def encrypt_file(self, file_path):
        """Encrypt a file and return encrypted data"""
        if not self.cipher_suite:
            raise ValueError("No encryption key set")
            
        with open(file_path, 'rb') as file:
            file_data = file.read()
        encrypted_data = self.cipher_suite.encrypt(file_data)
        return encrypted_data
    
    def decrypt_file(self, encrypted_data):
        """Decrypt encrypted data"""
        if not self.cipher_suite:
            raise ValueError("No encryption key set")
            
        return self.cipher_suite.decrypt(encrypted_data)
    
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
    
    args = parser.parse_args()
    
    orion = OrionH()
    orion.generate_key()
    
    try:
        if args.action == 'hide':
            if not args.source or not args.container:
                parser.error("hide action requires --source and --container arguments")
            orion.hide_file(args.source, args.container)
            print(f"File hidden successfully in {args.container}")
            
        elif args.action == 'extract':
            if not args.container or not args.output:
                parser.error("extract action requires --container and --output arguments")
            orion.extract_file(args.container, args.output)
            print(f"File extracted successfully to {args.output}")
            
    except Exception as e:
        print(f"Error: {str(e)}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
