from pathlib import Path

def hide_file(Volkoff, source_path: str | Path, output_path: Path | None = None) -> Path:
    """Hide encrypted file data"""
    # Create Volkoff directory if it doesn't exist
    output_dir = Path('Volkoff')
    output_dir.mkdir(exist_ok=True)

    if output_path is None:
        output_path = output_dir / f"{Path(source_path).stem}.safetensors"

    # Create output directory if it doesn't exist
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Read source file
    with open(source_path, "rb") as f:
        file_data = f.read()

    # Create fully encrypted container with all metadata
    original_ext = Path(source_path).suffix
    stored_data = Volkoff.encrypt_container(Volkoff.key, original_ext, file_data)

    # Save to file
    with open(output_path, 'wb') as f:
        f.write(stored_data)

    return output_path
