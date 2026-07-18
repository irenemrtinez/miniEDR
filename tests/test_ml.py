import unittest
import os
import sys
import shutil
import tempfile
from pathlib import Path

# Force python to find the modules in the workspace roots
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

try:
    from src.ml_detector import MLEnricher
    import src.ml_detector as ml_mod
except ModuleNotFoundError:
    from ml_detector import MLEnricher
    import ml_detector as ml_mod


class TestMLEnricher(unittest.TestCase):

    def setUp(self):
        """Creates a sandboxed environment for testing features dataset accumulation."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.temp_dir_path = Path(self.temp_dir.name)
        
        # Override the dataset CSV path dynamically to avoid modifying real data
        self.original_dataset_path = ml_mod.DATASET_PATH
        ml_mod.DATASET_PATH = os.path.join(str(self.temp_dir_path), 'features_dataset.csv')
        
        # Instantiate model for test evaluations
        self.enricher = MLEnricher(contamination_rate=0.1)

    def tearDown(self):
        """Restores original project constants and purges physical filesystem mock tracks."""
        ml_mod.DATASET_PATH = self.original_dataset_path
        self.temp_dir.cleanup()

    def generate_clean_telemetry_batch(self, count=20):
        """Helper method to spawn mock normal background processes telemetry with variance."""
        batch = []
        for i in range(count):
            # Introduce safe variance using index modulations
            cpu_val = 0.1 + (i % 5) * 0.4        # Ranges from 0.1% to 1.7%
            mem_val = 0.5 + (i % 4) * 0.3        # Ranges from 0.5% to 1.4%
            threads_val = 2 + (i % 3)            # 2, 3 or 4 threads
            connections_val = i % 2              # 0 or 1 connection
            
            # Recalculate thread ratio dynamically based on variance parameters
            ratio = connections_val / threads_val

            batch.append({
                "pid": 2000 + i,
                "name": f"legit_service_{i}.exe",
                "path": f"C:\\Program Files\\LegitApp\\service_{i}.exe",
                "username": "NT AUTHORITY\\SYSTEM",
                "cpu_percent": cpu_val,
                "memory_percent": mem_val,
                "num_threads": threads_val,
                "num_connections": connections_val,
                "is_temp_execution": 0,
                "is_system_user": 1,
                "connection_per_thread_ratio": ratio
            })
        return batch

    def test_feature_columns_alignment(self):
        """Verify MLEnricher checks for all our newly introduced contextual security features."""
        expected_features = [
            'cpu_percent', 'memory_percent', 'num_threads', 'num_connections',
            'is_temp_execution', 'is_system_user', 'connection_per_thread_ratio'
        ]
        self.assertEqual(self.enricher.feature_columns, expected_features)

    def test_ignored_processes_whitelist_filtering(self):
        """Confirm that processes added to the ignore list bypass inference and never flag anomalies."""
        # Train model first so we can trigger the predict logic flow
        clean_data = self.generate_clean_telemetry_batch()
        self.enricher.train(clean_data)
        
        # Create a malicious process footprint but assign it a whitelisted system name
        ignored_proc_sample = {
            "pid": 999,
            "name": "System Idle Process",
            "path": "",
            "username": "SYSTEM",
            "cpu_percent": 99.9,
            "memory_percent": 80.0,
            "num_threads": 1,
            "num_connections": 500,
            "is_temp_execution": 1,
            "is_system_user": 1,
            "connection_per_thread_ratio": 500.0
        }
        
        # The evaluation must return False regardless of its outlier statistics
        is_anomaly = self.enricher.predict_anomaly(ignored_proc_sample)
        self.assertFalse(is_anomaly)

    def test_training_and_anomaly_prediction(self):
        """Verify model establishes baseline boundaries and catches an obvious behavioral outlier."""
        clean_data = self.generate_clean_telemetry_batch(count=25)
        success = self.enricher.train(clean_data)
        self.assertTrue(success)
        self.assertTrue(self.enricher.is_trained)
        
        # Normal process lookup check
        normal_proc = clean_data[0]
        self.assertFalse(self.enricher.predict_anomaly(normal_proc))
        
        # Clear outlier fingerprint: executing from Temp, highly elevated connection-per-thread ratio
        anomaly_proc = {
            "pid": 6666,
            "name": "rev_shell.exe",
            "path": "C:\\Users\\Victim\\AppData\\Local\\Temp\\rev_shell.exe",
            "username": "Administrator",
            "cpu_percent": 45.0,
            "memory_percent": 35.0,
            "num_threads": 1,
            "num_connections": 85,
            "is_temp_execution": 1,
            "is_system_user": 1,
            "connection_per_thread_ratio": 85.0
        }
        
        is_anomaly = self.enricher.predict_anomaly(anomaly_proc)
        self.assertTrue(is_anomaly)

    def test_save_to_dataset_file_generation(self):
        """Ensure save_to_dataset writes data cleanly inside the new root data directory mapping."""
        sample_proc = self.generate_clean_telemetry_batch(count=1)[0]
        self.enricher.save_to_dataset(sample_proc, label=0)
        
        self.assertTrue(os.path.isfile(ml_mod.DATASET_PATH))


if __name__ == "__main__":
    unittest.main()