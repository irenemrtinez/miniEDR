import unittest
from unittest.mock import patch
import os
import tempfile
from pathlib import Path
import json
import hashlib

# Import the file analyzer functionalities
from src.file_analyzer import (
    calculate_hash,
    scan_directory_executables,
    save_files_to_disk
)


class TestFileAnalyzer(unittest.TestCase):

    def setUp(self):
        """Set up a temporary directory environment for realistic filesystem operations."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)

    def tearDown(self):
        """Clean up the temporary directory environment after tests run."""
        self.temp_dir.cleanup()

    # ---------------------------------------------------------
    # TESTS FOR: calculate_hash
    # ---------------------------------------------------------

    def test_calculate_hash_success(self):
        """Verify accurate calculation of MD5 and SHA-256 hashes for a standard text file in binary mode."""
        test_file = self.temp_dir_path / "test.txt"
        payload = b"miniEDR_secret_payload"
        test_file.write_bytes(payload)

        # Generate expected hashes dynamically from the exact same bytes to avoid system discrepancies
        expected_md5 = hashlib.md5(payload).hexdigest()
        expected_sha256 = hashlib.sha256(payload).hexdigest()

        md5, sha256 = calculate_hash(str(test_file))

        self.assertEqual(md5, expected_md5)
        self.assertEqual(sha256, expected_sha256)

    def test_calculate_hash_empty_file(self):
        """Verify that empty files or zero-byte virtual aliases return None gracefully without attempting to hash."""
        empty_file = self.temp_dir_path / "empty.exe"
        empty_file.write_bytes(b"")  # 0 bytes

        md5, sha256 = calculate_hash(str(empty_file))
        self.assertIsNone(md5)
        self.assertIsNone(sha256)

    @patch("builtins.open", side_effect=PermissionError)
    def test_calculate_hash_permission_error(self, mock_file):
        """Verify that files with restricted operating system permissions return None silently instead of crashing."""
        md5, sha256 = calculate_hash("restricted.exe")
        self.assertIsNone(md5)
        self.assertIsNone(sha256)

    @patch("builtins.open", side_effect=OSError)
    def test_calculate_hash_os_error(self, mock_file):
        """Verify that operating system read errors (like Windows execution aliases) are handled safely returning None."""
        md5, sha256 = calculate_hash("uwp_alias.exe")
        self.assertIsNone(md5)
        self.assertIsNone(sha256)

    # ---------------------------------------------------------
    # TESTS FOR: scan_directory_executables
    # ---------------------------------------------------------

    def test_scan_directory_executables_success(self):
        """Verify that only targeted executable extensions are scanned and correctly mapped with metadata."""
        # Create different file types inside our temporary sandbox
        exe_file = self.temp_dir_path / "payload.exe"
        exe_file.write_bytes(b"windows_executable")

        txt_file = self.temp_dir_path / "readme.txt"
        txt_file.write_bytes(b"regular_text_document")

        results = scan_directory_executables(str(self.temp_dir_path))

        # Only 'payload.exe' should be picked up based on target extensions, readme.txt is filtered out
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["name"], "payload.exe")
        self.assertEqual(results[0]["extension"], ".exe")
        self.assertEqual(results[0]["size_bytes"], len(b"windows_executable"))
        self.assertIn("md5", results[0])
        self.assertIn("sha256", results[0])
        self.assertFalse(results[0]["vt_scanned"])

    def test_scan_directory_invalid_path(self):
        """Verify that scanning a non-existent directory returns an empty telemetry list safely."""
        results = scan_directory_executables("C:\\NonExistentDirectory_EDR_Test")
        self.assertEqual(results, [])

    # ---------------------------------------------------------
    # TESTS FOR: save_files_to_disk
    # ---------------------------------------------------------

    def test_save_files_to_disk_deduplication(self):
        """Verify that file telemetry persistence correctly appends new discoveries while preventing duplicate SHA-256 hashes."""
        output_json = self.temp_dir_path / "files_telemetry.json"

        # 1. Save initial batch of files
        initial_batch = [
            {
                "name": "malware.exe",
                "path": "C:\\malware.exe",
                "sha256": "aaaa1111",
                "vt_scanned": False
            }
        ]
        save_files_to_disk(initial_batch, output_file=str(output_json))

        # 2. Try saving a new batch containing one duplicate and one unique file
        new_batch = [
            {
                "name": "malware.exe",
                "path": "C:\\Windows\\Temp\\malware.exe",  # Different path, but same SHA-256 (Duplicate!)
                "sha256": "aaaa1111",
                "vt_scanned": False
            },
            {
                "name": "beacon.dll",
                "path": "C:\\beacon.dll",  # Unique file!
                "sha256": "bbbb2222",
                "vt_scanned": False
            }
        ]
        save_files_to_disk(new_batch, output_file=str(output_json))

        # 3. Read saved database to ensure deduplication succeeded
        with open(output_json, "r", encoding="utf-8") as f:
            saved_data = json.load(f)

        # Total elements in JSON must be exactly 2 (malware.exe and beacon.dll), preventing duplicate insertion
        self.assertEqual(len(saved_data), 2)
        self.assertEqual(saved_data[0]["sha256"], "aaaa1111")
        self.assertEqual(saved_data[1]["sha256"], "bbbb2222")

    def test_save_files_to_disk_corrupted_json(self):
        """Verify graceful recovery and clean database rewrite when encountering a corrupted JSON storage file."""
        output_json = self.temp_dir_path / "corrupted_telemetry.json"

        # Write corrupted JSON manually to the real temporary directory to avoid brittle mocking
        with open(output_json, "w", encoding="utf-8") as f:
            f.write("{invalid_json_corrupted_on_power_loss...")

        new_files = [{"name": "rescue.exe", "sha256": "cccc3333"}]

        # This call should succeed by recovering gracefully from the read failure and rewriting the database
        try:
            save_files_to_disk(new_files, output_file=str(output_json))
            success = True
        except Exception:
            success = False

        self.assertTrue(success)

        # Verify the database was indeed rewritten cleanly
        with open(output_json, "r", encoding="utf-8") as f:
            saved_data = json.load(f)
        self.assertEqual(len(saved_data), 1)
        self.assertEqual(saved_data[0]["sha256"], "cccc3333")


if __name__ == "__main__":
    unittest.main()