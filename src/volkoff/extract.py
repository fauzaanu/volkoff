from pathlib import Path

def extract_file(Volkoff, safetensors_path: str | Path, output_path: Path) -> None:
    """Extract and decrypt hidden file"""
    # Load the stored data
    with open(safetensors_path, 'rb') as f:
        stored_data = f.read()

    # Split extension and encrypted data
    original_ext, encrypted_data = stored_data.split(b'###EXT###', 1)
    original_ext = original_ext.decode()

    # Decrypt the data
    decrypted_data = Volkoff.decrypt_file(encrypted_data)

    # Write decrypted data to output file
    with open(output_path, 'wb') as output:
        output.write(decrypted_data)
