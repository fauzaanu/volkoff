import os
import tempfile
from pathlib import Path
import pytest
from orionh.main import OrionH

@pytest.fixture
def test_file():
    """Create a temporary test file"""
    with tempfile.NamedTemporaryFile(suffix='.txt', delete=False) as f:
        f.write(b"Test content")
    yield Path(f.name)
    os.unlink(f.name)

@pytest.fixture
def orion():
    """Create OrionH instance with a fixed key for testing"""
    return OrionH("TEST_KEY_123")

def test_encryption_key_generation():
    """Test that encryption keys are generated correctly"""
    orion = OrionH()
    assert isinstance(orion.encryption_key, str)
    assert len(orion.encryption_key) > 0

def test_hide_and_extract(test_file, orion, tmp_path):
    """Test the full hide and extract workflow"""
    # Hide the file
    output_path = orion.hide_file(test_file)
    assert output_path.exists()
    
    # Extract the file
    extract_path = tmp_path / f"recovered_{test_file.stem}{test_file.suffix}"
    orion.extract_file(output_path, extract_path)
    
    # Verify contents
    assert extract_path.exists()
    assert extract_path.read_bytes() == test_file.read_bytes()

def test_incorrect_key(test_file, tmp_path):
    """Test that extraction fails with wrong key"""
    # Hide with one key
    orion1 = OrionH("KEY1")
    output_path = orion1.hide_file(test_file)
    
    # Try to extract with different key
    orion2 = OrionH("KEY2")
    extract_path = tmp_path / f"recovered_{test_file.stem}{test_file.suffix}"
    
    with pytest.raises(ValueError, match="Incorrect decryption key"):
        orion2.extract_file(output_path, extract_path)

def test_file_extension_preservation(test_file, orion, tmp_path):
    """Test that file extensions are preserved during hide/extract"""
    # Create test file with specific extension
    test_path = tmp_path / "test.xyz"
    test_path.write_bytes(b"Test content")
    
    # Hide and extract
    output_path = orion.hide_file(test_path)
    extract_path = tmp_path / f"recovered_{test_path.stem}{test_path.suffix}"
    orion.extract_file(output_path, extract_path)
    
    assert extract_path.suffix == ".xyz"

def test_invalid_file(orion, tmp_path):
    """Test handling of non-existent files"""
    with pytest.raises(FileNotFoundError):
        orion.hide_file(tmp_path / "nonexistent.txt")
