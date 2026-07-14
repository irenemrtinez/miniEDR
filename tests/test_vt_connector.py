import unittest
from unittest.mock import patch, MagicMock
import requests

# Import the VirusTotal connector functionalities
from src.vt_connector import check_file_hash_vt


class TestVTConnector(unittest.TestCase):

    # ---------------------------------------------------------
    # TESTS FOR: check_file_hash_vt
    # ---------------------------------------------------------

    @patch("src.vt_connector.VT_API_KEY", None)
    def test_check_hash_missing_api_key(self):
        """Verify that the connector returns a PENDING status gracefully if the VirusTotal API key is missing."""
        results = check_file_hash_vt("any_sha256_hash")
        self.assertEqual(results, {"vt_status": "PENDING"})

    @patch("src.vt_connector.VT_API_KEY", "fake_api_key_for_testing")
    @patch("requests.get")
    def test_check_hash_vt_found_clean(self, mock_get):
        """Verify dynamic parsing of a valid, positive, clean response (0 detections) from the VirusTotal API."""
        # Mocking a successful response from VirusTotal with 0 malicious engines
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 60,
                        "type-unsupported": 4,
                        "suspicious": 0,
                        "confirmed-timeout": 0,
                        "timeout": 0,
                        "failure": 0,
                        "malicious": 0,
                        "undetected": 10
                    },
                    "first_submission_date": 1451606400,
                    "magic": "PE32 executable (GUI) Intel 80386, for MS Windows",
                    "names": ["clean_app.exe", "installer.exe"]
                }
            }
        }
        mock_get.return_value = mock_response

        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        results = check_file_hash_vt(sha256)

        self.assertEqual(results["vt_status"], "CLEAN")
        self.assertEqual(results["vt_positives"], 0)
        self.assertEqual(results["vt_total_vendors"], 74)  # Sum of all analysis stats
        self.assertEqual(results["vt_magic"], "PE32 executable (GUI) Intel 80386, for MS Windows")
        self.assertEqual(results["vt_alternative_names"], ["clean_app.exe", "installer.exe"])
        self.assertIn("vt_analyzed_at", results)

    @patch("src.vt_connector.VT_API_KEY", "fake_api_key_for_testing")
    @patch("requests.get")
    def test_check_hash_vt_found_suspicious(self, mock_get):
        """Verify that a file flagged with malicious detections is marked as SUSPICIOUS and its key metadata is extracted."""
        # Mocking a positive/malicious response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "harmless": 10,
                        "malicious": 45,
                        "suspicious": 5,
                        "undetected": 10
                    },
                    "first_submission_date": 1700000000,
                    "magic": "MS-DOS executable, MZ for MS-DOS",
                    "names": ["malware.exe", "payload.exe", "backdoor.exe", "extra.exe"]
                }
            }
        }
        mock_get.return_value = mock_response

        sha256 = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
        results = check_file_hash_vt(sha256)

        self.assertEqual(results["vt_status"], "SUSPICIOUS")
        self.assertEqual(results["vt_positives"], 45)
        self.assertEqual(results["vt_total_vendors"], 70)  # Sum: 10 + 45 + 5 + 10
        self.assertEqual(results["vt_magic"], "MS-DOS executable, MZ for MS-DOS")
        # Keep TOP 3 names according to the slice: names[:3]
        self.assertEqual(results["vt_alternative_names"], ["malware.exe", "payload.exe", "backdoor.exe"])

    @patch("src.vt_connector.VT_API_KEY", "fake_api_key_for_testing")
    @patch("requests.get")
    def test_check_hash_vt_not_found(self, mock_get):
        """Verify that a 404 response from the API is successfully translated into a NOT_FOUND status with clean default fields."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        results = check_file_hash_vt("unknown_sha256_hash")

        self.assertEqual(results["vt_status"], "NOT_FOUND")
        self.assertEqual(results["vt_positives"], 0)
        self.assertEqual(results["vt_total_vendors"], 0)
        self.assertIsNone(results["vt_first_submission"])
        self.assertEqual(results["vt_magic"], "Unknown binary data")
        self.assertEqual(results["vt_alternative_names"], [])

    @patch("src.vt_connector.VT_API_KEY", "fake_api_key_for_testing")
    @patch("requests.get")
    def test_check_hash_vt_api_error(self, mock_get):
        """Verify that HTTP error codes (like 403 or 500) trigger a fallback to PENDING status without crashing."""
        mock_response = MagicMock()
        mock_response.status_code = 403  # Forbidden / Expired API Key
        mock_response.text = "Forbidden"
        mock_get.return_value = mock_response

        results = check_file_hash_vt("any_sha256_hash")
        self.assertEqual(results, {"vt_status": "PENDING"})

    @patch("src.vt_connector.VT_API_KEY", "fake_api_key_for_testing")
    @patch("requests.get", side_effect=requests.exceptions.Timeout("Connection timed out"))
    def test_check_hash_vt_connection_exception(self, mock_get):
        """Verify that network timeouts or connection exceptions are caught safely and return a PENDING status."""
        results = check_file_hash_vt("any_sha256_hash")
        self.assertEqual(results, {"vt_status": "PENDING"})


if __name__ == "__main__":
    unittest.main()