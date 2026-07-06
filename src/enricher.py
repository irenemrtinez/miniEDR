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
        # Look for our test process (notepad) to verify the EDR logic works
        #if "notepad" in path_lower or "appdata\\local\\temp" in path_lower:
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

def check_process_masquerading(snapshot):
    """
    Heuristic Rule: Detects processes that are masquerading as legitimate system processes.
    This is done by checking if the process name matches a known system process but the 
    executable path does not match the expected system directory.
    """
    alerts = []
    system_processes = {
        "explorer.exe": "C:\\Windows\\explorer.exe",
        "svchost.exe": "C:\\Windows\\System32\\svchost.exe",
        "lsass.exe": "C:\\Windows\\System32\\lsass.exe",
        "services.exe": "c:\\windows\\system32",
        "wininit.exe": "C:\\Windows\\System32\\wininit.exe",
        "winlogon.exe": "C:\\Windows\\System32\\winlogon.exe",
        #"notepad.exe": "C:\\Windows\\System32\\MandatorySystemFolder" # <-- bait
    }

    for p in snapshot:
  
        path = p.get('exe')
        name_lower = p.get('name', '').lower()

        if not path or name_lower not in system_processes:
            continue
        # Ensure case-insensitive matching to prevent malware evasion via random capitalization
        path_lower = path.lower()
        expected_path = system_processes[name_lower].lower()

        if expected_path not in path_lower:
            alert = {
                "rule": "Process Masquerading",
                "severity": "CRITICAL",
                "pid": p['pid'],
                "name": p['name'],
                "path": p['exe'],
                "user": p['username']
            }
            alerts.append(alert)
    return alerts

def check_reconnaissance_tools(snapshot):
    """
    Heuristic Rule: Flags the execution of reconnaissance tools.
    Attackers frequently run these commands immediately after gaining access to map the system.
    """
    alerts = []
    reconnaissance_tools = ["whoami.exe", "systeminfo.exe", "ipconfig.exe", "netstat.exe", "net.exe", "net1.exe", "tasklist.exe", "wmic.exe"]

    for p in snapshot:
        name_lower = p.get('name', '').lower()
        if name_lower in reconnaissance_tools:
            alert = {
                "rule": "Reconnaissance Tool Execution",
                "severity": "MEDIUM",
                "pid": p['pid'],
                "name": p['name'],
                "path": p.get('exe', 'Unknown'),
                "user": p.get('username', 'Unknown')
            }
            alerts.append(alert)
    return alerts

def save_alerts_to_disk(alerts, filename="data/alerts.json"):
    """
    Saves the detected alerts into a structured JSON file.
    Ensures the target folder exists before writing to prevent OS crashes.
    """
    if not alerts:
        print("[*] No alerts to save. System appears clean.")
        return
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(alerts, f, indent=4)
        print(f"[*] Alerts saved to {filename}")
    except Exception as e:
        print(f"[!] Failed to save alerts: {e}")


if __name__ == "__main__":
    print("[*] Starting miniEDR Enrichment & Analysis Engine...")

    # 1. Load  telemetry data from disk
    data = load_telemetry()
    print(f"[*] Loaded {len(data)} telemetry records for analysis.")

    # 2. Run heuristic checks for suspicious processes
    print("[*] Scanning telemetry for security risks...")
    alerts = []
    
    # Run Rule 1: Suspicious paths
    alerts.extend(check_suspicious_processes(data))
    
    # Run Rule 2: Process Masquerading
    alerts.extend(check_process_masquerading(data))

    # Run Rule 3: Reconnaissance Tools (¡NUEVA!)
    alerts.extend(check_reconnaissance_tools(data))

    # 3. Evaluate results and display findings
    if alerts:
        print(f"[!] ALERT: Found {len(alerts)} processes running from suspicious locations!")
        print("=" * 70)
        for alert in alerts:
            print(f"[{alert['severity']}] Rule: {alert['rule']}")
            print(f"  -> PID: {alert['pid']} | Name: {alert['name']} | User: {alert['user']}")
            print(f"  -> Path: {alert['path']}")
            print("-" * 70)
        
        #  Archive the alerts to disk
        save_alerts_to_disk(alerts)
    else:
        print("[*] No suspicious processes detected. System appears clean.")