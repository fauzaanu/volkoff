# Volkoff

A simple script to encrypt and decrypt files.

Install as a package globally with:

```bash
pip install volkoff
```

And then run from anywhere with

```bash
vk
```

## How Strong is the Encryption?

Volkoff uses multiple layers of strong encryption and security measures:

- AES-256 encryption for file contents
- ECDSA with SECP256k1 curve (same as Bitcoin) for signatures
- PBKDF2 key derivation with 1,000,000 iterations
- Multiple entropy sources for key generation:
  - System random (os.urandom)
  - High-precision timestamps
  - Process-specific data
- Double-hashing of keys using SHA-512 and SHA-256
- Unique salt for each encrypted file

## Best Practices for Using Volkoff

1. **Backup Your Keys**: The encryption key shown after hiding a file is the ONLY way to recover your data. Store it securely!

2. **Secure Key Storage**:
   - Never store keys in plain text
   - Consider using a password manager
   - Split keys across different secure locations for critical files

3. **File Management**:
   - Keep original files until you verify successful encryption/decryption
   - Use meaningful filenames to identify encrypted content
   - Store encrypted files separately from their keys

4. **Testing**:
   - Always test decryption of important files immediately after encryption
   - Verify file integrity after decryption
   - Practice recovery procedures regularly
