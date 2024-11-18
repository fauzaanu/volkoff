from pathlib import Path

def extract_file(Volkoff, safetensors_path: str | Path, output_path: Path) -> None:
    """Extract and decrypt hidden file"""
    # Load the stored data
    with open(safetensors_path, 'rb') as f:
        stored_data = f.read()

    # Decrypt the entire container
    private_key, original_ext, decrypted_data = Volkoff.decrypt_container(stored_data)
    
    # Verify the provided key matches the stored private key
    if private_key != Volkoff.key:
        raise ValueError("Invalid decryption key")

    # Write decrypted data to output file
    with open(output_path, 'wb') as output:
        output.write(decrypted_data)
