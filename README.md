# OrionH - Bitcoin-Style File Encryption and Hiding Tool

OrionH is a powerful file encryption and hiding tool that implements Bitcoin-style cryptography for secure file operations. The name is inspired by Charles Buttowski's Father, whose code name is ORION.

## Features

- Bitcoin-style cryptography using SECP256k1 curve
- ECDSA-based file signing and verification
- File hiding capabilities within container files
- Command-line interface for easy operation
- Secure key generation and management
- Bitcoin-style address generation

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/orionH.git
cd orionH
```

2. Install required dependencies:
```bash
pip install ecdsa base58
```

## Usage

OrionH provides two main operations: hiding files and extracting hidden files.

### Hiding a File

To hide a file within a container file:

```bash
python main.py hide --source <source_file> [--container <container_file>]
```

Example:
```bash
python main.py hide --source secret.txt --container image.jpg

# Or let it generate a container image automatically:
python main.py hide --source secret.txt
```

When hiding a file, the program will generate and display a secure encryption key. **SAVE THIS KEY** in a password manager like Bitwarden - you will need it to decrypt your files later!

### Extracting a Hidden File

To extract a hidden file from a container, using your saved encryption key:

```bash
python main.py extract --container <container_file> --output <output_file> --key <your-saved-key>
```

Example:
```bash
python main.py extract --container image.jpg --output recovered_secret.txt --key "YOUR-SAVED-ENCRYPTION-KEY"
```

IMPORTANT: There is NO WAY to recover your files if you lose the encryption key. Always store it securely in a password manager!

## How It Works

OrionH uses a combination of Bitcoin-style cryptography and modern encryption to secure your files. Here's the detailed process:

### Key Generation
1. Generates a private key using the SECP256k1 elliptic curve (the same one Bitcoin uses)
2. Derives a public key from the private key using elliptic curve mathematics
3. Creates a Bitcoin-style address from the public key using:
   - SHA-256 hashing
   - RIPEMD160 hashing
   - Base58Check encoding

### File Encryption Process
1. When hiding a file:
   - Generates a salt and derives an encryption key using PBKDF2 with:
     - SHA-256 as the hash function
     - 480,000 iterations
     - 32-byte key length
   - Encrypts the file data using Fernet (AES-128 in CBC mode)
   - Creates a SHA-256 hash of the encrypted data
   - Signs the hash with the private key using ECDSA
   - Combines the encrypted data, salt, and signature
   - Appends the result to the container file with special markers (###ORION###)

2. When extracting a file:
   - Locates the hidden data using the markers
   - Separates the encrypted data, salt, and signature
   - Verifies the signature using the public key
   - Derives the same encryption key using the stored salt
   - Decrypts the data using Fernet

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Fauzaan Gasim

## Acknowledgments

- Inspired by Bitcoin's cryptographic standards
- Named after the ORION codename from Kick Buttowski
