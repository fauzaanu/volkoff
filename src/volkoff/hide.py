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

    # Store private key and original extension with encrypted data
    private_key_hex = Volkoff.private_key.to_string().hex()
    original_ext = Path(source_path).suffix
    stored_data = f"{private_key_hex}###KEY###{original_ext}###EXT###".encode() + encrypted_data

    # Save to file
    with open(output_path, 'wb') as f:
        f.write(stored_data)

    return output_path
