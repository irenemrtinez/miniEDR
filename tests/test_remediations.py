import unittest
from unittest.mock import patch
import os
import tempfile
from pathlib import Path
from cryptography.fernet import Fernet

# Import the remediation functionalities
from src import remediations
from src.remediations import (
    delete_file_from_disk,
    quarantine_file,
    restore_file_from_quarantine
)


class TestRemediations(unittest.TestCase):

    def setUp(self):
        """Set up a sandboxed temporary environment for safe quarantine testing."""
        # Create a temporary directory to act as our system root
        self.temp_root = tempfile.TemporaryDirectory()
        self.temp_root_path = Path(self.temp_root.name)

        # Override the QUARANTINE_DIR and KEY_FILE variables dynamically
        self.original_quarantine_dir = remediations.QUARANTINE_DIR
        self.original_key_file = remediations.KEY_FILE

        remediations.QUARANTINE_DIR = str(self.temp_root_path / "quarantine")
        remediations.KEY_FILE = str(self.temp_root_path / "quarantine" / "vault.key")

    def tearDown(self):
        """Clean up the sandboxed environment and restore original variables."""
        # Restore original module paths
        remediations.QUARANTINE_DIR = self.original_quarantine_dir
        remediations.KEY_FILE = self.original_key_file

        # Destroy temp files
        self.temp_root.cleanup()

    # =========================================================
    # COMPREHENSIVE INTEGRATION & STATE-TRANSITION FLOWS
    # =========================================================

    def test_flow_delete_then_quarantine(self):
        """FLOW: Verify that deleting a file and then attempting to quarantine it fails gracefully."""
        target_file = self.temp_root_path / "transient_malware.exe"
        target_file.write_bytes(b"active_ransomware_payload")

        # 1. First, delete the file from disk successfully
        del_success, del_msg = delete_file_from_disk(str(target_file))
        self.assertTrue(del_success)
        self.assertFalse(target_file.exists())

        # 2. Immediately try to quarantine the same file
        # It must fail because the physical file is no longer present on the filesystem
        q_success, q_msg = quarantine_file(str(target_file), "AL-101")
        self.assertFalse(q_success)
        self.assertIn("not found on disk", q_msg)

    def test_flow_quarantine_double_restore_and_delete(self):
        """FLOW: Run a full lifecycle (Quarantine -> Restore -> Block Duplicate Restore -> Final Delete)."""
        original_payload = b"state_machine_test_bytes"
        source_file = self.temp_root_path / "agent.exe"
        source_file.write_bytes(original_payload)

        # 1. Quarantine the active file
        alert_id = "AL-555"
        q_success, q_filename = quarantine_file(str(source_file), alert_id)
        self.assertTrue(q_success)
        self.assertFalse(source_file.exists())  # Must be gone from origin

        # 2. Restore it back to life
        restore_path = self.temp_root_path / "agent_restored.exe"
        res_success, res_msg = restore_file_from_quarantine(q_filename, str(restore_path))
        self.assertTrue(res_success)
        self.assertTrue(restore_path.exists())
        self.assertEqual(restore_path.read_bytes(), original_payload)

        # 3. Attempt to restore it a SECOND time (Replay Attack / Error simulation)
        # It must fail because the quarantined (.vir) file was cleanly deleted during the first restore
        res_double_success, res_double_msg = restore_file_from_quarantine(q_filename, str(restore_path))
        self.assertFalse(res_double_success)
        self.assertIn("not found", res_double_msg)

        # 4. Final Cleanup: Delete the restored file to verify disk hygiene
        final_del_success, final_del_msg = delete_file_from_disk(str(restore_path))
        self.assertTrue(final_del_success)
        self.assertFalse(restore_path.exists())

    def test_flow_tampering_during_quarantine(self):
        """FLOW: Handle critical failures where the file disappears mid-quarantine process."""
        source_file = self.temp_root_path / "unstable.exe"
        source_file.write_bytes(b"dynamic_payload")

        # We simulate a race condition where open() succeeds, but os.remove() fails
        # because an external process (or an AV) locked/removed the file first
        with patch("os.remove", side_effect=FileNotFoundError("File vanished")):
            success, message = quarantine_file(str(source_file), "AL-909")
            
            # The quarantine will fail because it cannot complete the transaction safely
            self.assertFalse(success)
            self.assertIn("Failed to quarantine file", message)

    # =========================================================
    # CLASSIC ISOLATED UNIT TESTS
    # =========================================================

    def test_delete_file_success(self):
        """Verify that a target malicious file is successfully erased from disk."""
        target_file = self.temp_root_path / "malware.exe"
        target_file.write_bytes(b"evil_payload")

        self.assertTrue(target_file.exists())
        success, message = delete_file_from_disk(str(target_file))

        self.assertTrue(success)
        self.assertFalse(target_file.exists())
        self.assertIn("Successfully deleted", message)

    def test_delete_file_not_found(self):
        """Verify that attempting to delete a non-existent file returns success smoothly."""
        non_existent = str(self.temp_root_path / "ghost.exe")
        success, message = delete_file_from_disk(non_existent)

        self.assertTrue(success)
        self.assertIn("not found on disk", message)

    @patch("os.remove", side_effect=PermissionError("Access denied"))
    def test_delete_file_permission_error(self, mock_remove):
        """Verify that permission failures during deletion are safely caught."""
        target_file = self.temp_root_path / "system32_mimic.exe"
        target_file.write_bytes(b"locked")

        success, message = delete_file_from_disk(str(target_file))
        self.assertFalse(success)
        self.assertIn("Permission denied", message)

    def test_quarantine_file_not_found(self):
        """Verify that trying to quarantine a non-existent file path returns an error."""
        success, message = quarantine_file("C:\\NonExistentFile.exe", "AL-100")
        self.assertFalse(success)
        self.assertIn("not found on disk", message)

    def test_restore_file_not_found(self):
        """Verify that restoring a non-existent quarantine payload fails gracefully."""
        restore_path = self.temp_root_path / "revived.exe"
        success, message = restore_file_from_quarantine("non_existent_malware.vir", str(restore_path))

        self.assertFalse(success)
        self.assertIn("not found", message)


if __name__ == "__main__":
    unittest.main()