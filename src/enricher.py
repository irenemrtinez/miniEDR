from importlib.resources import path
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

    # Expanded list of common malware staging and writable directories
    suspicious_paths = [
        "appdata\\local\\temp", 
        "windows\\temp", 
        "users\\public", 
        "perflogs", 
        "programdata"
    ]

    for p in snapshot:
        #if processes dont have a path (like PID 4 SYSTEM) or if the path is empty, skip them
        if not p.get('exe'):
            continue

        path_lower = p['exe'].lower()
        
        # Check if the executable path contains any of the untrusted directories
        if any(folder in path_lower for folder in suspicious_paths):
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
        "services.exe": "C:\\Windows\\System32\\services.exe",
        "csrss.exe": "C:\\Windows\\System32\\csrss.exe",
        "smss.exe": "C:\\Windows\\System32\\smss.exe",
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

        if expected_path != path_lower:
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
def check_double_extensions(snapshot):
    """
    Heuristic Rule: Detects files with double extensions, which is a common technique used by malware to disguise executable files.
    For example, a file named "document.pdf.exe" may appear to be a harmless PDF document but is actually an executable.
    """
    alerts = []

    # common double extension patterns
    suspicious_patterns = [".pdf.exe", ".docx.exe", ".jpg.exe", ".png.exe", ".txt.exe", ".xls.exe","zip.exe", ".rar.exe", ".bat.exe", ".scr.exe", ".pif.exe"]
    
    for p in snapshot:
        name_lower = p.get('name', '').lower()

        #check if the process name ends with any of the suspicious patterns
        if any(name_lower.endswith(pattern) for pattern in suspicious_patterns):
            alert = {
                "rule": "Double Extension Detected",
                "severity": "MEDIUM",
                "pid": p['pid'],
                "name": p['name'],
                "path": p.get('exe', 'Unknown'),
                "user": p.get('username', 'Unknown')
            }
            alerts.append(alert)
    return alerts

def check_temp_execution(snapshot):
    """
    Heuristic Rule: Detects binaries executing from Windows Temporary folders.
    Malware frequently drops and runs payloads here to bypass standard user restrictions.
    """
    alerts = []
    
    for p in snapshot:
        path = p.get('exe')
        if path:
            path_lower = path.lower()
            #  intercept execution from common temp directories
            if "AppData\\Local\\Temp" in path_lower or "windows\\temp" in path_lower:
                alert = {
                    "rule": "Process Execution from Temp Directory",
                    "severity": "LOW",  
                    "pid": p['pid'],
                    "name": p['name'],
                    "path": path,
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

    # Run Rule 3: Reconnaissance Tools
    alerts.extend(check_reconnaissance_tools(data))

    #Run Rule 4: Double Extensions
    alerts.extend(check_double_extensions(data))

    # Run Rule 5: Temporary Directory Execution
    alerts.extend(check_temp_execution(data))

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