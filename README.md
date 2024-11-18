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

## How the Encryption Works

Here's exactly what happens when you encrypt a file:

1. **Key Generation**: 
   - A random 32-byte (256-bit) key is generated using os.urandom
   - This key is converted to a hex string that you need to save

2. **File Container Format**:
   - Your file's extension is saved (like .jpg, .pdf)
   - The file data is combined with its extension
   - This creates a container: "extension|filedata"

3. **Encryption Process**:
   - A fresh 12-byte random number (nonce) is generated
   - The container is encrypted using AES-256 in GCM mode
   - The nonce is prepended to the encrypted data
   - Format: [nonce][encrypted_data]

4. **Decryption Process**:
   - Your saved key is used to initialize AES-256-GCM
   - The first 12 bytes are split off as the nonce
   - The rest is decrypted using your key and the nonce
   - The original extension and file data are extracted