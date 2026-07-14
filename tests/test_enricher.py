import unittest
from unittest.mock import patch, mock_open
import json
import os

# Import the enricher functionalities
from src.enricher import (
    load_telemetry,
    check_suspicious_processes,
    check_process_masquerading,
    check_reconnaissance_tools,
    check_double_extensions,
    check_temp_execution,
    check_reverse_shell,
    check_virustotal_malicious_files,
    save_alerts_to_disk
)


class TestEnricherRules(unittest.TestCase):

    # ---------------------------------------------------------
    # TESTS FOR: load_telemetry
    # ---------------------------------------------------------

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data='[{"pid": 123, "name": "test.exe"}]')
    def test_load_telemetry_success(self, mock_file, mock_exists):
        """Verify successful loading and parsing of a structured telemetry JSON database file."""
        data = load_telemetry("fake_path.json")
        self.assertEqual(len(data), 1)
        self.assertEqual(data[0]["pid"], 123)

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open, read_data='{corrupted_json...')
    def test_load_telemetry_corrupted(self, mock_file, mock_exists):
        """Verify graceful error handling and empty list fallback when encountering a corrupted telemetry JSON structure."""
        data = load_telemetry("fake_path.json")
        self.assertEqual(data, [])

    # ---------------------------------------------------------
    # TESTS FOR: check_suspicious_processes
    # ---------------------------------------------------------

    def test_check_suspicious_processes(self):
        """Verify detection and high-severity flagging of processes executing from untrusted staging folders like Temp or Public."""
        fake_snapshot = [
            {"pid": 100, "name": "legit.exe", "exe": "C:\\Program Files\\Legit\\legit.exe", "username": "Irene"},
            {"pid": 101, "name": "malware.exe", "exe": "C:\\Users\\Public\\malware.exe", "username": "Irene"},
            {"pid": 102, "name": "system_proc", "exe": None, "username": "SYSTEM"}  # Empty path verification
        ]
        alerts = check_suspicious_processes(fake_snapshot)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Suspicious Execution Path")
        self.assertEqual(alerts[0]["severity"], "HIGH")
        self.assertEqual(alerts[0]["pid"], 101)

    # ---------------------------------------------------------
    # TESTS FOR: check_process_masquerading
    # ---------------------------------------------------------

    def test_check_process_masquerading(self):
        """Verify critical-severity alerting when a common system utility executes from an illegitimate workspace."""
        fake_snapshot = [
            {"pid": 200, "name": "explorer.exe", "exe": "c:\\windows\\explorer.exe", "username": "Irene"},  # Legit path
            {"pid": 201, "name": "svchost.exe", "exe": "C:\\Users\\Irene\\Downloads\\svchost.exe", "username": "Irene"},  # Masqueraded
            {"pid": 202, "name": "random.exe", "exe": "C:\\Windows\\System32\\random.exe", "username": "SYSTEM"}  # Ignored name
        ]
        alerts = check_process_masquerading(fake_snapshot)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Process Masquerading")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["pid"], 201)

    # ---------------------------------------------------------
    # TESTS FOR: check_reconnaissance_tools
    # ---------------------------------------------------------

    def test_check_reconnaissance_tools(self):
        """Verify mapping and detection of operational discovery and enumeration tools like whoami.exe or ipconfig.exe."""
        fake_snapshot = [
            {"pid": 300, "name": "whoami.exe", "exe": "C:\\Windows\\System32\\whoami.exe", "username": "Irene"},
            {"pid": 301, "name": "chrome.exe", "exe": "C:\\Program Files\\Chrome\\chrome.exe", "username": "Irene"}
        ]
        alerts = check_reconnaissance_tools(fake_snapshot)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Reconnaissance Tool Execution")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(alerts[0]["name"], "whoami.exe")

    # ---------------------------------------------------------
    # TESTS FOR: check_double_extensions
    # ---------------------------------------------------------

    def test_check_double_extensions(self):
        """Verify mitigation of file extension spoofing techniques such as executing a disguised document.pdf.exe payload."""
        fake_snapshot = [
            {"pid": 400, "name": "invoice.pdf.exe", "exe": "C:\\Users\\Irene\\Downloads\\invoice.pdf.exe", "username": "Irene"},
            {"pid": 401, "name": "clean_doc.docx", "exe": "C:\\Users\\Irene\\Documents\\clean_doc.docx", "username": "Irene"}
        ]
        alerts = check_double_extensions(fake_snapshot)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Double Extension Detected")
        self.assertEqual(alerts[0]["severity"], "MEDIUM")
        self.assertEqual(alerts[0]["name"], "invoice.pdf.exe")

    # ---------------------------------------------------------
    # TESTS FOR: check_temp_execution
    # ---------------------------------------------------------

    def test_check_temp_execution(self):
        """Verify identification and low-severity classification of standard binaries spawned out of local AppData Temp zones."""
        fake_snapshot = [
            {"pid": 500, "name": "installer.exe", "exe": "C:\\Users\\Irene\\AppData\\Local\\Temp\\installer.exe", "username": "Irene"},
            {"pid": 501, "name": "word.exe", "exe": "C:\\Program Files\\Word\\word.exe", "username": "Irene"}
        ]
        alerts = check_temp_execution(fake_snapshot)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Process Execution from Temp Directory")
        self.assertEqual(alerts[0]["severity"], "LOW")
        self.assertEqual(alerts[0]["pid"], 500)

    # ---------------------------------------------------------
    # TESTS FOR: check_reverse_shell
    # ---------------------------------------------------------

    def test_check_reverse_shell_detected(self):
        """Verify critical correlation alerts when an active command interpreter holds an ESTABLISHED remote network socket."""
        fake_snapshot = [
            {
                "pid": 600,
                "name": "powershell.exe",
                "exe": "C:\\Windows\\System32\\powershell.exe",
                "username": "Irene",
                "connections": [
                    {"local_address": "192.168.1.10:49200", "remote_address": "8.8.8.8:443", "status": "ESTABLISHED"}
                ]
            }
        ]
        alerts = check_reverse_shell(fake_snapshot)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Reverse Shell Detected")
        self.assertEqual(alerts[0]["severity"], "CRITICAL")
        self.assertEqual(alerts[0]["remote_address"], "8.8.8.8:443")

    def test_check_reverse_shell_no_connection(self):
        """Verify that standard shell interpreters without active network channels do not trigger false alerts."""
        fake_snapshot = [
            {
                "pid": 601,
                "name": "cmd.exe",
                "exe": "C:\\Windows\\System32\\cmd.exe",
                "username": "Irene",
                "connections": []  # Local interactive terminal session
            }
        ]
        alerts = check_reverse_shell(fake_snapshot)
        self.assertEqual(len(alerts), 0)

    # ---------------------------------------------------------
    # TESTS FOR: check_virustotal_malicious_files
    # ---------------------------------------------------------

    @patch("os.path.exists", return_value=True)
    @patch("builtins.open", new_callable=mock_open)
    def test_check_virustotal_malicious_files_various_severities(self, mock_file, mock_exists):
        """Verify dynamic escalation of alert severities based on positive VirusTotal engine detections."""
        fake_files_data = [
            {
                "name": "clean.exe",
                "path": "C:\\clean.exe",
                "vt_status": "CLEAN"
            },
            {
                "name": "suspicious_info.exe",
                "path": "C:\\susp_info.exe",
                "vt_status": "SUSPICIOUS",
                "vt_positives": 3,
                "vt_total_vendors": 70,
                "vt_analyzed_at": "2026-07-14T19:00:00"
            },
            {
                "name": "dangerous_critical.exe",
                "path": "C:\\critical.exe",
                "vt_status": "SUSPICIOUS",
                "vt_positives": 45,
                "vt_total_vendors": 70,
                "vt_analyzed_at": "2026-07-14T19:05:00"
            }
        ]
        # Return serialized telemetry database upon mock reading
        mock_file.return_value.read.return_value = json.dumps(fake_files_data)

        alerts = check_virustotal_malicious_files("dummy_path.json")

        self.assertEqual(len(alerts), 2)
        # Check Info severity mapping (positives = 3)
        self.assertEqual(alerts[0]["severity"], "INFO")
        self.assertEqual(alerts[0]["name"], "suspicious_info.exe")
        # Check Critical severity mapping (positives = 45)
        self.assertEqual(alerts[1]["severity"], "CRITICAL")
        self.assertEqual(alerts[1]["name"], "dangerous_critical.exe")

    # ---------------------------------------------------------
    # TESTS FOR: save_alerts_to_disk
    # ---------------------------------------------------------

    @patch("os.path.exists", return_value=True)
    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_save_alerts_to_disk_lifecycle(self, mock_file, mock_makedirs, mock_exists):
        """Verify historical alert persistence, deduplication, and dynamic process state changes (RUNNING to TERMINATED)."""
        # Historical snapshot has an alert from PID 777.
        # This execution detects PID 888 (new) and PID 777 is not in the new scan (so it must transition to TERMINATED).
        historical_alerts = [
            {
                "rule": "Suspicious Execution Path",
                "severity": "HIGH",
                "pid": 777,
                "name": "zombie_malware.exe",
                "path": "C:\\Windows\\Temp\\zombie_malware.exe",
                "user": "Irene",
                "status": "RUNNING",
                "timestamp": "2026-07-14T18:00:00"
            }
        ]
        
        new_alerts = [
            {
                "rule": "Process Masquerading",
                "severity": "CRITICAL",
                "pid": 888,
                "name": "svchost.exe",
                "path": "C:\\Users\\Irene\\Downloads\\svchost.exe",
                "user": "Irene"
            }
        ]

        # Feed the mock file reader with existing history
        mock_file.return_value.read.return_value = json.dumps(historical_alerts)

        save_alerts_to_disk(new_alerts, filename="dummy_alerts.json")

        # Capture arguments serialized to JSON upon writing
        written_data = "".join(call.args[0] for call in mock_file.return_value.write.call_args_list)
        parsed_output = json.loads(written_data)

        # Output should have 2 historical logs now (1 new running alert, 1 historical terminated alert)
        self.assertEqual(len(parsed_output), 2)
        
        # Verify status transitions
        alert_888 = next(a for a in parsed_output if a["pid"] == 888)
        alert_777 = next(a for a in parsed_output if a["pid"] == 777)

        self.assertEqual(alert_888["status"], "RUNNING")
        self.assertEqual(alert_777["status"], "TERMINATED")


if __name__ == "__main__":
    unittest.main()