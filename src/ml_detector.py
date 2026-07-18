import pandas as pd
from sklearn.ensemble import IsolationForest
import os
import csv

# Path where we will accumulate real telemetry for future retraining/analysis
DATASET_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'features_dataset.csv')

class MLEnricher:
    def __init__(self, contamination_rate=0.01):
        """
        Step 1 & 2 of Scikit-Learn API: Choose model class and set hyperparameters.
        We instantiate IsolationForest. 'contamination' defines the expected proportion 
        of outliers (anomalies) in the training dataset.
        """
        self.model = IsolationForest(contamination=contamination_rate, random_state=42)
        self.is_trained = False
        # Define the exact features we want to extract (Feature Engineering)
        self.feature_columns = ['cpu_percent', 'memory_percent', 'num_threads', 'num_connections', 'is_temp_execution','is_system_user',
                                'connection_per_thread_ratio']
        #processes to ignore
        self.ignored_processes = {'System Idle Process', 'Idle', 'System', 'python.exe', 'registry'}
        
    def _feature_engineering(self, raw_processes):
        """
        Step 3 of Scikit-Learn API: Format raw data into a features matrix (X).
        Transforms the raw telemetry list of dicts into a structured pandas DataFrame.
        """
        df = pd.DataFrame(raw_processes)
        
        # If no processes are provided, return an empty DataFrame with expected columns
        if df.empty:
            return pd.DataFrame(columns=self.feature_columns)

        # Ensure all required numeric features exist in the DataFrame
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0.0

        # Fill any missing/null values (Imputation) to avoid Scikit-Learn crashes
        df[self.feature_columns] = df[self.feature_columns].fillna(0.0)

        # Return only the numerical feature matrix X
        return df[self.feature_columns]

    def train(self, historical_data):
        """
        Step 4 of Scikit-Learn API: Fit the estimator to the training data.
        The model 'learns' the boundary of normal process behavior.
        """
        if len(historical_data) < 15:
            print("[!] Not enough baseline telemetry data to train the ML model.")
            return False

        # Extract features and fit the model
        X_train = self._feature_engineering(historical_data)
        self.model.fit(X_train)
        self.is_trained = True
        print("[+] Behavior-based ML model successfully trained on local workspace.")
        return True

    def predict_anomaly(self, live_process):
        """
        Step 5 of Scikit-Learn API: Predict labels for new data.
        Returns True if the model detects a behavioral anomaly (-1), False otherwise (1).
        """
        if not self.is_trained:
            return False  # Do not flag alerts if the model hasn't established a baseline yet
        
        if str(live_process.get('name', '')).strip() in self.ignored_processes:
            return False

        # Prepare the single process sample as a 2D matrix
        X_new = self._feature_engineering([live_process])
        
        # IsolationForest returns -1 for anomalies and 1 for normal instances
        prediction = self.model.predict(X_new)[0]
        return prediction == -1

    def save_to_dataset(self, live_process, label=0):
        """
        Utility Method: Saves the engineered features to a CSV file.
        This allows building a local historical dataset from live production telemetry.
        """
        os.makedirs(os.path.dirname(DATASET_PATH), exist_ok=True)
        file_exists = os.path.isfile(DATASET_PATH)
        
        # Format the process to extract the correct features
        X_df = self._feature_engineering([live_process])
        if X_df.empty:
            return
            
        features_list = X_df.iloc[0].tolist()
        
        with open(DATASET_PATH, mode='a', newline='') as f:
            writer = csv.writer(f)
            if not file_exists:
                # CSV Headers: Feature names + target label
                writer.writerow(self.feature_columns + ['label'])
            writer.writerow(features_list + [label])