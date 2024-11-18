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
python main.py hide --source <source_file> --container <container_file>
```

Example:
```bash
python main.py hide --source secret.txt --container image.jpg
```

### Extracting a Hidden File

To extract a hidden file from a container:

```bash
python main.py extract --container <container_file> --output <output_file>
```

Example:
```bash
python main.py extract --container image.jpg --output recovered_secret.txt
```

## How It Works

OrionH uses Bitcoin-style cryptography to secure your files. Here's the detailed process:

### Key Generation
1. Generates a private key using the SECP256k1 elliptic curve (the same one Bitcoin uses)
2. Derives a public key from the private key using elliptic curve mathematics
3. Creates a Bitcoin-style address from the public key using:
   - SHA-256 hashing
   - RIPEMD160 hashing
   - Base58Check encoding

### File Encryption Process
1. When hiding a file:
   - Reads the source file's contents
   - Creates a SHA-256 hash of the file data
   - Signs the hash with the private key using ECDSA
   - Combines the original file data with the signature
   - Appends the result to the container file with special markers

2. When extracting a file:
   - Locates the hidden data using the markers
   - Separates the file data from the signature
   - Verifies the signature using the public key
   - If verification succeeds, recovers the original file

### Security Features and Limitations

While OrionH implements strong cryptographic primitives, users should be aware of these security considerations:

1. Key Management Vulnerabilities:
   - Private keys are generated fresh each time the program runs
   - Keys are not persisted between sessions
   - No key backup mechanism exists
   - Keys are held in memory during program execution

2. Steganographic Weaknesses:
   - The presence of hidden data is detectable due to obvious markers (###ORION###)
   - The end of the container file can be easily examined to find hidden content
   - No attempt to disguise the presence of hidden data

3. Implementation Limitations:
   - No encryption of the file contents (only signing)
   - Raw file data is stored in plaintext
   - Signature only proves authenticity, not confidentiality
   - No protection against replay attacks

4. Container File Vulnerabilities:
   - Multiple writes to the same container file will append multiple copies
   - No size limits on container files
   - No validation of container file integrity

For actual secure file storage, consider using:
- Full disk encryption
- Dedicated encryption tools like VeraCrypt
- Proper key management systems
- True steganographic techniques

The current implementation is primarily educational and demonstrates Bitcoin-style cryptographic concepts.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Fauzaan Gasim

## Acknowledgments

- Inspired by Bitcoin's cryptographic standards
- Named after the ORION codename from Kick Buttowski
