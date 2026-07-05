import json
import os

def load_telemetry(filename="data/telemetry.json"):
    """
    Loads the telemetry data from a JSON file.
    Returns an empty list if the file doesn't exist or is empty.
    """
    if not os.path.exists(filename):
        print(f"[-] Telemetry file not found at {filename}. Is the agent running?")
        return []
    
    try:
        with open(filename,"r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"[!] Failed to decode JSON from {filename}. The file may be corrupted.")
        return []
    
def check_suspicious_processes(snapshot):
    """
    Heuristic Rule: Flags processes running from temporary or user-writable 
    directories, which is a common technique used by malware to evade detection.
    """
    alerts = []

    for p in snapshot:
        #if processes dont have a path (like PID 4 SYSTEM) or if the path is empty, skip them
        if not p.get('exe'):
            continue

        path_lower = p['exe'].lower()
        
        #look for execution in critical temporary or user-writeable locations
        if "appdata\\local\\temp" in path_lower or "windows\\temp" in path_lower:
            alert = {
                "rule": "Suspicious Execution Path",
                "severity": "HIGH",
                "pid": p['pid'],
                "name": p['name'],
                "path": p['exe'],
                "user": p['username']
            }
            alerts.append(alert)
            
    return alerts


if __name__ == "__main__":
    print("[*] Starting miniEDR Enrichment & Analysis Engine...")

    # 1. Load  telemetry data from disk
    data = load_telemetry()
    print(f"[*] Loaded {len(data)} telemetry records for analysis.")

    # 2. Run heuristic checks for suspicious processes
    print("[*] Scanning telemetry for security risks...")
    alerts = check_suspicious_processes(data)

    # 3. Evaluate results and display findings
    if alerts:
        print(f"[!] ALERT: Found {len(alerts)} processes running from suspicious locations!")
        print("=" * 70)
        for alert in alerts:
            print(f"[{alert['severity']}] Rule: {alert['rule']}")
            print(f"  -> PID: {alert['pid']} | Name: {alert['name']} | User: {alert['user']}")
            print(f"  -> Path: {alert['path']}")
            print("-" * 70)
    else:
        print("[*] No suspicious processes detected. System appears clean.")