import tempfile
import unittest
from pathlib import Path
from .main import VolkoffH

class TestVolkoffH(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures before each test method"""
        # Create a temporary test file
        self.test_dir = Path(tempfile.mkdtemp())
        self.test_file = self.test_dir / "test.txt"
        self.test_file.write_bytes(b"Test content")

        # Create VolkoffH instance with a fixed key for testing
        self.Volkoff = VolkoffH("TEST_KEY_123")

        # Create temporary directory for output files
        self.tmp_path = Path(tempfile.mkdtemp())

    def tearDown(self):
        """Clean up after each test method"""
        # Clean up all temporary files and directories
        if hasattr(self, 'test_dir') and self.test_dir.exists():
            for file in self.test_dir.glob("*"):
                file.unlink()
            self.test_dir.rmdir()

        if hasattr(self, 'tmp_path') and self.tmp_path.exists():
            for file in self.tmp_path.glob("*"):
                file.unlink()
            self.tmp_path.rmdir()

    def test_encryption_key_generation(self):
        """Test that encryption keys are generated correctly"""
        Volkoff = VolkoffH()
        self.assertIsInstance(Volkoff.encryption_key, str)
        self.assertGreater(len(Volkoff.encryption_key), 0)

    def test_hide_and_extract(self):
        """Test the full hide and extract workflow"""
        # Hide the file
        output_path = self.Volkoff.hide_file(self.test_file)
        self.assertTrue(output_path.exists())

        # Extract the file
        extract_path = self.tmp_path / f"{self.test_file.stem}{self.test_file.suffix}"
        self.Volkoff.extract_file(output_path, extract_path)

        # Verify contents
        self.assertTrue(extract_path.exists())
        self.assertEqual(extract_path.read_bytes(), self.test_file.read_bytes())

    def test_incorrect_key(self):
        """Test that extraction fails with wrong key"""
        # Hide with one key
        Volkoff1 = VolkoffH("KEY1")
        output_path = Volkoff1.hide_file(self.test_file)

        # Try to extract with different key
        Volkoff2 = VolkoffH("KEY2")
        extract_path = self.tmp_path / f"{self.test_file.stem}{self.test_file.suffix}"

        with self.assertRaisesRegex(ValueError, "Incorrect decryption key"):
            Volkoff2.extract_file(output_path, extract_path)

    def test_file_extension_preservation(self):
        """Test that file extensions are preserved during hide/extract"""
        # Create test file with specific extension
        test_path = self.tmp_path / "test.xyz"
        test_path.write_bytes(b"Test content")

        # Hide and extract
        output_path = self.Volkoff.hide_file(test_path)
        extract_path = self.tmp_path / f"{test_path.stem}{test_path.suffix}"
        self.Volkoff.extract_file(output_path, extract_path)

        self.assertEqual(extract_path.suffix, ".xyz")

    def test_invalid_file(self):
        """Test handling of non-existent files"""
        with self.assertRaises(FileNotFoundError):
            self.Volkoff.hide_file(self.tmp_path / "nonexistent.txt")

if __name__ == '__main__':
    unittest.main()
