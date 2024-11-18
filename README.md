# Volkoff

A secure file encryption tool using AES-256-GCM encryption.

Installation:
```bash
pip install volkoff
```

Launch with:
```bash
vk
```

## Implementation Details

Encryption Process:
1. Generates a 256-bit AES key for secure encryption
2. Creates a container format that includes:
   - File extension metadata
   - Original file contents
   - Unique 12-byte nonce for each encryption
3. Encrypts the entire container using AES-256-GCM
4. Returns the encryption key for secure storage

Decryption Process:
1. Validates the provided encryption key
2. Extracts the nonce from the encrypted container
3. Decrypts the container to retrieve:
   - Original file extension
   - File contents
4. Reconstructs the file with original metadata

## Security Features

- AES-256-GCM authenticated encryption
- Unique nonce generation per file
- Secure container format preserving file metadata
- Authentication to prevent tampering

Important Security Notes:
- Store encryption keys securely - they cannot be recovered
- Maintain secure backups of encryption keys
- Verify successful decryption after encrypting critical files

## Disclaimer

The author and contributors are not responsible for any data loss or corruption that may occur while using this software. Users are strongly advised to:

- Keep secure backups of all important files before encryption
- Safely store encryption keys in multiple locations
- Test the decryption process on non-critical files first
- Verify successful decryption immediately after encryption
