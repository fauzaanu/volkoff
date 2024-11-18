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

Volkoff uses industry-standard encryption and security measures:

- AES-256-GCM (Galois/Counter Mode) for authenticated encryption
- Cryptographically secure random key generation using os.urandom
- 256-bit (32-byte) encryption keys
- Unique 96-bit (12-byte) nonce for each encryption operation
- Built-in authentication to detect tampering
- Secure container format preserving file metadata

## Best Practices for Using Volkoff

1. **Backup Your Keys**: The encryption key shown after hiding a file is the ONLY way to recover your data. Store it securely!

2. **Secure Key Storage**:
   - Never store keys in plain text files
   - Use a password manager to store encryption keys
   - Keep backups of keys in secure locations
   - Consider using a hardware security key or encrypted USB drive

3. **File Management**:
   - Keep original files until you verify successful encryption/decryption
   - Use descriptive filenames that don't reveal sensitive content
   - Store encrypted files separately from their keys
   - Regularly test your backup and recovery procedures

4. **Security Considerations**:
   - Use strong, unique keys for each important file
   - Don't share keys through insecure channels like email or chat
   - Clear clipboard after copying keys
   - Be cautious when decrypting files from untrusted sources
