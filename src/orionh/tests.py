import tempfile
import unittest
from pathlib import Path
from orionh.main import OrionH
from orionh.hide import hide_file
from orionh.extract import extract_file

class TestOrionH(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures before each test method"""
        # Create a temporary test file
        self.test_file = Path(tempfile.mktemp(suffix='.txt'))
        self.test_file.write_bytes(b"Test content")
        
        # Create OrionH instance with a fixed key for testing
        self.orion = OrionH("TEST_KEY_123")
        
        # Create temporary directory for output files
        self.tmp_path = Path(tempfile.mkdtemp())
    
    def tearDown(self):
        """Clean up after each test method"""
        if self.test_file.exists():
            self.test_file.unlink()
        for file in self.tmp_path.glob("*"):
            file.unlink()
        self.tmp_path.rmdir()

    def test_encryption_key_generation(self):
        """Test that encryption keys are generated correctly"""
        orion = OrionH()
        self.assertIsInstance(orion.encryption_key, str)
        self.assertGreater(len(orion.encryption_key), 0)

    def test_hide_and_extract(self):
        """Test the full hide and extract workflow"""
        # Hide the file
        output_path = self.orion.hide_file(self.test_file)
        self.assertTrue(output_path.exists())
        
        # Extract the file
        extract_path = self.tmp_path / f"recovered_{self.test_file.stem}{self.test_file.suffix}"
        self.orion.extract_file(output_path, extract_path)
        
        # Verify contents
        self.assertTrue(extract_path.exists())
        self.assertEqual(extract_path.read_bytes(), self.test_file.read_bytes())

    def test_incorrect_key(self):
        """Test that extraction fails with wrong key"""
        # Hide with one key
        orion1 = OrionH("KEY1")
        output_path = orion1.hide_file(self.test_file)
        
        # Try to extract with different key
        orion2 = OrionH("KEY2")
        extract_path = self.tmp_path / f"recovered_{self.test_file.stem}{self.test_file.suffix}"
        
        with self.assertRaisesRegex(ValueError, "Incorrect decryption key"):
            orion2.extract_file(output_path, extract_path)

    def test_file_extension_preservation(self):
        """Test that file extensions are preserved during hide/extract"""
        # Create test file with specific extension
        test_path = self.tmp_path / "test.xyz"
        test_path.write_bytes(b"Test content")
        
        # Hide and extract
        output_path = self.orion.hide_file(test_path)
        extract_path = self.tmp_path / f"recovered_{test_path.stem}{test_path.suffix}"
        self.orion.extract_file(output_path, extract_path)
        
        self.assertEqual(extract_path.suffix, ".xyz")

    def test_invalid_file(self):
        """Test handling of non-existent files"""
        with self.assertRaises(FileNotFoundError):
            self.orion.hide_file(self.tmp_path / "nonexistent.txt")

if __name__ == '__main__':
    unittest.main()
