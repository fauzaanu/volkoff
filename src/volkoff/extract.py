from pathlib import Path

def extract_file(Volkoff, safetensors_path: str | Path, output_path: Path) -> None:
    """Extract and decrypt hidden file"""
    # Load the stored data
    with open(safetensors_path, 'rb') as f:
        stored_data = f.read()

    # Split private key, extension and encrypted data
    stored_key, rest = stored_data.split(b'###KEY###', 1)
    original_ext, encrypted_data = rest.split(b'###EXT###', 1)
    stored_key = stored_key.decode()
    original_ext = original_ext.decode()

    # Verify the key matches
    if stored_key != Volkoff.private_key.to_string().hex():
        raise ValueError("Incorrect decryption key")

    # Decrypt the data
    decrypted_data = Volkoff.decrypt_file(encrypted_data)

    # Write decrypted data to output file
    with open(output_path, 'wb') as output:
        output.write(decrypted_data)
