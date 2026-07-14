import unittest
from unittest.mock import patch, MagicMock, mock_open
import datetime
import os
import psutil

# Importing the agent module functions
from src.agent import get_network_connections, collect_running_processes, save_telemetry_to_disk


class TestAgentTelemetry(unittest.TestCase):

    # ---------------------------------------------------------
    # TESTS FOR: get_network_connections
    # ---------------------------------------------------------

    @patch("psutil.net_connections")
    def test_get_network_connections_success(self, mock_net_conns):
        """
        Verify that network connections are successfully grouped and mapped by their PID.
        """
        # Mocking two active system connections
        conn1 = MagicMock()
        conn1.pid = 1024
        conn1.laddr.ip = "127.0.0.1"
        conn1.laddr.port = 5000
        conn1.raddr.ip = "192.168.1.50"
        conn1.raddr.port = 443
        conn1.status = "ESTABLISHED"

        conn2 = MagicMock()
        conn2.pid = 2048
        conn2.laddr.ip = "0.0.0.0"
        conn2.laddr.port = 80
        conn2.raddr = None  # Local listening socket
        conn2.status = "LISTEN"

        mock_net_conns.return_value = [conn1, conn2]

        result = get_network_connections()

        # Assertions
        self.assertIn(1024, result)
        self.assertIn(2048, result)
        self.assertEqual(len(result[1024]), 1)
        self.assertEqual(result[1024][0]["local_address"], "127.0.0.1:5000")
        self.assertEqual(result[1024][0]["remote_address"], "192.168.1.50:443")
        self.assertEqual(result[2048][0]["remote_address"], None)
        self.assertEqual(result[2048][0]["status"], "LISTEN")

    @patch("psutil.net_connections")
    def test_get_network_connections_ignores_none_pid(self, mock_net_conns):
        """
        Ensure system connections with a missing PID are safely ignored.
        """
        conn = MagicMock()
        conn.pid = None  # No PID associated (common for system idle sockets)
        mock_net_conns.return_value = [conn]

        result = get_network_connections()
        self.assertEqual(result, {})

    @patch("psutil.net_connections")
    def test_get_network_connections_access_denied(self, mock_net_conns):
        """
        Verify that if the OS denies socket access, the function returns an empty map gracefully.
        """
        mock_net_conns.side_effect = psutil.AccessDenied()
        
        result = get_network_connections()
        self.assertEqual(result, {})

    # ---------------------------------------------------------
    # TESTS FOR: collect_running_processes
    # ---------------------------------------------------------

    @patch("src.agent.get_network_connections")
    @patch("psutil.process_iter")
    def test_collect_running_processes_success(self, mock_process_iter, mock_get_net):
        """
        Validate the complete collection loop: memory conversion to MB, timestamping, and network enrichment.
        """
        # Mocking active network connections
        mock_get_net.return_value = {
            9999: [{"local_address": "127.0.0.1:5000", "remote_address": None, "status": "LISTEN"}]
        }

        # Mocking a running process structure
        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 9999,
            "name": "python.exe",
            "ppid": 1111,
            "username": "Irene",
            "cpu_percent": 1.5,
            "exe": "C:\\Python\\python.exe",
            "create_time": 1600000000.0,
            "memory_info": MagicMock(rss=10 * 1024 * 1024)  # 10 Megabytes in bytes
        }
        mock_process_iter.return_value = [mock_proc]

        processes = collect_running_processes()

        self.assertEqual(len(processes), 1)
        proc_data = processes[0]
        
        # Validations
        self.assertEqual(proc_data["pid"], 9999)
        self.assertEqual(proc_data["memory_usage_mb"], 10.0)  # Verify memory conversion logic
        self.assertNotIn("memory_info", proc_data)  # Cleaned up to avoid JSON serialization failures
        self.assertIn("timestamp", proc_data)
        self.assertEqual(len(proc_data["connections"]), 1)
        self.assertEqual(proc_data["connections"][0]["local_address"], "127.0.0.1:5000")

    @patch("src.agent.get_network_connections")
    @patch("psutil.process_iter")
    def test_collect_running_processes_with_none_memory(self, mock_process_iter, mock_get_net):
        """
        Ensure that if memory consumption returns None, the agent maps it to 0.0 MB securely.
        """
        mock_get_net.return_value = {}
        mock_proc = MagicMock()
        mock_proc.info = {
            "pid": 5555,
            "memory_info": None
        }
        mock_process_iter.return_value = [mock_proc]

        processes = collect_running_processes()
        self.assertEqual(processes[0]["memory_usage_mb"], 0.0)

    @patch("psutil.process_iter")
    def test_collect_running_processes_tolerates_exceptions(self, mock_process_iter):
        """
        Validate that ephemeral process dropouts (zombies, system restrictions) are safely bypassed.
        """
        # Mocking 3 processes: NoSuchProcess, ZombieProcess, and a valid process
        proc_fail1 = MagicMock()
        type(proc_fail1).info = property(MagicMock(side_effect=psutil.NoSuchProcess(111)))

        proc_fail2 = MagicMock()
        type(proc_fail2).info = property(MagicMock(side_effect=psutil.ZombieProcess(222)))

        proc_ok = MagicMock()
        proc_ok.info = {
            "pid": 333,
            "memory_info": None
        }

        mock_process_iter.return_value = [proc_fail1, proc_fail2, proc_ok]

        processes = collect_running_processes()
        
        # Only the successful process must persist in our telemetry array
        self.assertEqual(len(processes), 1)
        self.assertEqual(processes[0]["pid"], 333)

    # ---------------------------------------------------------
    # TESTS FOR: save_telemetry_to_disk
    # ---------------------------------------------------------

    @patch("os.makedirs")
    @patch("builtins.open", new_callable=mock_open)
    def test_save_telemetry_to_disk_success(self, mock_file, mock_makedirs):
        """
        Verify that directories are verified/created and telemetry data is serialized successfully.
        """
        fake_data = [{"pid": 123, "name": "test_process"}]
        
        save_telemetry_to_disk(fake_data, filename="custom_path/telemetry.json")

        # Confirm directory presence verification
        mock_makedirs.assert_called_once_with("custom_path", exist_ok=True)
        # Verify write operations are safely opened
        mock_file.assert_called_once_with("custom_path/telemetry.json", "w", encoding="utf-8")

    @patch("os.makedirs")
    @patch("builtins.open", side_effect=PermissionError("Permission Denied"))
    def test_save_telemetry_to_disk_exception_handling(self, mock_file, mock_makedirs):
        """
        Verify that file write failures (e.g., system permissions) are caught without crashing the agent.
        """
        fake_data = [{"pid": 123}]
        
        # This call must not raise any exceptions to the parent execution thread
        try:
            save_telemetry_to_disk(fake_data, filename="restricted_dir/telemetry.json")
            success = True
        except Exception:
            success = False
            
        self.assertTrue(success)


if __name__ == "__main__":
    unittest.main()