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

## Security Features

- Uses SECP256k1 elliptic curve (same as Bitcoin)
- Implements SHA-256 and RIPEMD160 hashing
- Base58Check encoding for addresses
- Digital signatures for file authenticity
- Secure key generation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Author

Fauzaan Gasim

## Acknowledgments

- Inspired by Bitcoin's cryptographic standards
- Named after the ORION codename from Kick Buttowski
