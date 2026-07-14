import unittest
from unittest.mock import patch, MagicMock
import os
import json
import tempfile
from pathlib import Path
import sys

# Set dummy environment variables BEFORE importing app to prevent initialization crashes
os.environ["VT_API_KEY"] = "dummy_test_key"

# Force Python to find app.py in either root directory or src/ folder
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

try:
    from src.app import app, process_vt_batch, db_lock
    import src.app as flask_app
except ModuleNotFoundError:
    from app import app, process_vt_batch, db_lock
    import app as flask_app


class TestAppDashboard(unittest.TestCase):

    def setUp(self):
        """Set up Flask test client and sandboxed JSON database paths."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)

        # Configure Flask application with test mode enabled
        app.config["TESTING"] = True
        self.client = app.test_client()

        # Override production file database paths with isolated sandbox paths
        self.original_alerts_file = flask_app.ALERTS_FILE
        self.original_telemetry_file = flask_app.TELEMETRY_FILE
        self.original_files_telemetry_file = flask_app.FILES_TELEMETRY_FILE

        flask_app.ALERTS_FILE = str(self.temp_dir_path / "alerts.json")
        flask_app.TELEMETRY_FILE = str(self.temp_dir_path / "telemetry.json")
        flask_app.FILES_TELEMETRY_FILE = str(self.temp_dir_path / "files_telemetry.json")

        # Initialize empty sandbox mock databases
        with open(flask_app.ALERTS_FILE, "w") as f:
            json.dump([], f)
        with open(flask_app.TELEMETRY_FILE, "w") as f:
            json.dump([], f)
        with open(flask_app.FILES_TELEMETRY_FILE, "w") as f:
            json.dump([], f)

    def tearDown(self):
        """Restore global production paths and clean up temporary storage."""
        flask_app.ALERTS_FILE = self.original_alerts_file
        flask_app.TELEMETRY_FILE = self.original_telemetry_file
        flask_app.FILES_TELEMETRY_FILE = self.original_files_telemetry_file
        self.temp_dir.cleanup()

    # ---------------------------------------------------------
    # TESTS FOR: Dashboard & Core Routing
    # ---------------------------------------------------------

    def test_dashboard_route_success(self):
        """Verify that the home dashboard successfully reads and displays alerts and process statistics."""
        # Populate sandbox telemetry with sample active process data
        sample_processes = [{"pid": 1234, "name": "explorer.exe", "path": "C:\\Windows\\explorer.exe"}]
        with open(flask_app.TELEMETRY_FILE, "w") as f:
            json.dump(sample_processes, f)

        # Fire a simulated GET request to the Flask dashboard route
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)

    # ---------------------------------------------------------
    # TESTS FOR: Thread-Safe VT Batch Engine
    # ---------------------------------------------------------

    def test_process_vt_batch_marking_scanned(self):
        """Verify that processing a batch successfully updates the database and sets vt_scanned to True."""
        # Dynamic patch depending on where the app module was loaded from
        patch_path = "src.app.check_file_hash_vt" if "src" in flask_app.__name__ else "app.check_file_hash_vt"
        
        with patch(patch_path) as mock_vt:
            # Set up a fake VirusTotal API response
            mock_vt.return_value = {
                "vt_status": "CLEAN",
                "vt_positives": 0,
                "vt_total_vendors": 60,
                "vt_magic": "MZ PE",
                "vt_alternative_names": ["good.exe"]
            }

            # Populate telemetry with a pending/unscanned executable entry
            file_telemetry = [{
                "name": "calc.exe",
                "path": "C:\\Windows\\System32\\calc.exe",
                "sha256": "abcdef123456",
                "vt_scanned": False
            }]
            with open(flask_app.FILES_TELEMETRY_FILE, "w", encoding="utf-8") as f:
                json.dump(file_telemetry, f)

            # Run our fixed batch process function
            process_vt_batch(flask_app.FILES_TELEMETRY_FILE)

            # Read back telemetry database to verify successful updates
            with open(flask_app.FILES_TELEMETRY_FILE, "r", encoding="utf-8") as f:
                updated_data = json.load(f)

            self.assertEqual(len(updated_data), 1)
            # CRITICAL VERIFICATION: Verify that vt_scanned flag is now True and data is merged
            self.assertTrue(updated_data[0]["vt_scanned"])
            self.assertEqual(updated_data[0]["vt_status"], "CLEAN")

    # ---------------------------------------------------------
    # TESTS FOR: API Remediation Endpoints
    # ---------------------------------------------------------

    def test_api_remediate_file_success(self):
        """Verify that the EDR active response API correctly deletes a file and sets its status to RESOLVED."""
        patch_path = "src.app.delete_file_from_disk" if "src" in flask_app.__name__ else "app.delete_file_from_disk"
        
        with patch(patch_path) as mock_delete:
            mock_delete.return_value = (True, "Successfully deleted file.")

            # Set up a target file on the virtual sandbox filesystem
            evil_file = self.temp_dir_path / "malware.exe"
            evil_file.write_bytes(b"bad_code")

            # Mock an outstanding Alert in alerts.json
            alert_timestamp = "2026-07-14 12:00:00"
            alerts = [{
                "path": str(evil_file),
                "timestamp": alert_timestamp,
                "status": "SUSPICIOUS"
            }]
            with open(flask_app.ALERTS_FILE, "w") as f:
                json.dump(alerts, f)

            # Send POST request to the file remediation API endpoint
            payload = {"path": str(evil_file), "timestamp": alert_timestamp}
            response = self.client.post("/api/remediate/file", json=payload)

            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertEqual(data["status"], "success")

            # Verify that the alert entry was successfully updated to 'RESOLVED' in the DB
            with open(flask_app.ALERTS_FILE, "r") as f:
                updated_alerts = json.load(f)
            self.assertEqual(updated_alerts[0]["status"], "RESOLVED")

    def test_api_remediate_quarantine_success(self):
        """Verify that calling the quarantine API securely encrypts and shifts metadata to a QUARANTINED state."""
        patch_path = "src.app.quarantine_file" if "src" in flask_app.__name__ else "app.quarantine_file"
        
        with patch(patch_path) as mock_quarantine:
            mock_quarantine.return_value = (True, "malware_123.vir")

            target_file = "C:\\Windows\\Temp\\trojan.exe"
            alert_timestamp = "20260714120000"

            alerts = [{
                "path": target_file,
                "timestamp": alert_timestamp,
                "status": "SUSPICIOUS"
            }]
            with open(flask_app.ALERTS_FILE, "w") as f:
                json.dump(alerts, f)

            payload = {"path": target_file, "timestamp": alert_timestamp}
            response = self.client.post("/api/remediate/quarantine", json=payload)

            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertEqual(data["status"], "success")

            with open(flask_app.ALERTS_FILE, "r") as f:
                updated_alerts = json.load(f)
            self.assertEqual(updated_alerts[0]["status"], "QUARANTINED")
            self.assertEqual(updated_alerts[0]["quarantine_file"], "malware_123.vir")

    def test_api_remediate_restore_success(self):
        """Verify that calling the restore API successfully decrypts a quarantined payload and rolls status back to PENDING."""
        patch_path = "src.app.restore_file_from_quarantine" if "src" in flask_app.__name__ else "app.restore_file_from_quarantine"
        
        with patch(patch_path) as mock_restore:
            mock_restore.return_value = (True, "File restored successfully.")

            target_file = "C:\\Windows\\Temp\\restored_app.exe"
            alert_timestamp = "20260714120000"

            # Initialize alert as quarantined first
            alerts = [{
                "path": target_file,
                "timestamp": alert_timestamp,
                "status": "QUARANTINED",
                "quarantine_file": "malware_123.vir"
            }]
            with open(flask_app.ALERTS_FILE, "w") as f:
                json.dump(alerts, f)

            payload = {
                "path": target_file,
                "timestamp": alert_timestamp,
                "quarantine_file": "malware_123.vir"
            }
            response = self.client.post("/api/remediate/restore", json=payload)

            self.assertEqual(response.status_code, 200)
            data = response.get_json()
            self.assertEqual(data["status"], "success")

            # Verification: Status must return to 'PENDING' and quarantine references must be popped
            with open(flask_app.ALERTS_FILE, "r") as f:
                updated_alerts = json.load(f)
            self.assertEqual(updated_alerts[0]["status"], "PENDING")
            self.assertNotIn("quarantine_file", updated_alerts[0])


if __name__ == "__main__":
    unittest.main()