from pathlib import Path

def hide_file(Volkoff, source_path: str | Path, output_path: Path | None = None) -> Path:
    """Hide encrypted file data"""
    encrypted_data = Volkoff.encrypt_file(source_path)

    # Create Volkoff directory if it doesn't exist
    output_dir = Path('Volkoff')
    output_dir.mkdir(exist_ok=True)

    if output_path is None:
        output_path = output_dir / f"{Path(source_path).stem}.safetensors"

    # Create output directory if it doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Store encrypted private key and original extension with encrypted data
    original_ext = Path(source_path).suffix
    encrypted_private_key = Volkoff.encrypt_private_key()
    stored_data = encrypted_private_key + b"###KEY###" + original_ext.encode() + b"###EXT###" + encrypted_data

    # Save to file
    with open(output_path, 'wb') as f:
        f.write(stored_data)

    return output_path
