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

def check_reverse_shell(snapshot):
    """
    Heuristic Rule: Detects command interpreters (CMD, PowerShell, etc.) 
    with active network connections, which strongly indicates a Reverse Shell.
    """
    alerts = []
    shells = ["cmd.exe", "powershell.exe", "pwsh.exe", "PowerShell_ISE.exe", "wsl.exe"]

    for p in snapshot:
        name_lower = p.get('name', '').lower()

        if name_lower in shells:
            connections = p.get('connections', [])

            for conn in connections:
                if conn.get('status') == 'ESTABLISHED' and conn.get('remote_address'):
                    alert = {
                        "rule": "Reverse Shell Detected",
                        "severity": "CRITICAL",
                        "pid": p['pid'],
                        "name": p['name'],
                        "path": p.get('exe', 'Unknown'),
                        "user": p.get('username', 'Unknown'),
                        "remote_address": conn.get('remote_address', 'Unknown'),
                        "remote_port": conn.get('remote_port', 'Unknown')
                    }
                    alerts.append(alert)
                    break  # No need to check further connections for this process
    return alerts   

def check_virustotal_malicious_files(files_telemetry_path):
    """
    Evaluates analyzed files and generates security alerts for any item 
    flagged as SUSPICIOUS by VirusTotal intelligence.
    """
    vt_alerts = []
    if not os.path.exists(files_telemetry_path):
        print(f"[!] Files telemetry not found at {files_telemetry_path}. Skipping VirusTotal alert generation.")
        return vt_alerts

    try: 
        with open(files_telemetry_path, "r", encoding="utf-8") as f:
            files_data = json.load(f)
        for file_entry in files_data:
            #trigger alert only if virus total flagged the binary as suspicious (positives > 0)
            if file_entry.get("vt_status") == "SUSPICIOUS":
                    positives = file_entry.get("vt_positives", 0)
                    total = file_entry.get("vt_total_vendors", 0)     
                    # Assign critical severity if multiple vendors flag it, otherwise high
                    if 1 <= positives <= 4:
                        severity = "INFO"
                    elif 5 <= positives <= 9:
                        severity = "LOW"
                    elif 10 <= positives <= 29:
                        severity = "MEDIUM"
                    elif 30 <= positives <= 40:
                        severity = "HIGH"
                    else:
                        severity = "CRITICAL"
                     # Standardized EDR forensic alert payload
                    alert = {
                        "rule": "Malicious File Detected via VirusTotal",
                        "severity": severity,
                        "pid": "N/A",
                        "name": file_entry.get("name"),
                        "path": file_entry.get("path"),
                        "user": "System (Static Analysis)",
                        "remote_address": "N/A",
                        "remote_port": "N/A",
                        "status": f"DETECTED ({positives}/{total} Engines)",
                        "timestamp": file_entry.get("vt_analyzed_at")
                    }
                    vt_alerts.append(alert)

    except Exception as e:
        print(f"[!] Error evaluating VirusTotal alerts in enricher: {e}")
        
    return vt_alerts


import os
import json
import datetime

def save_alerts_to_disk(alerts, filename="data/alerts.json"):
    """
    Saves the detected alerts into a structured JSON file.
    Ensures the target folder exists before writing to prevent OS crashes.
    """
    # 1. Open the file and load existing alerts if any, to avoid overwriting
    existing_alerts = []
    if os.path.exists(filename):
        try: 
            with open(filename, "r", encoding="utf-8") as f:
                existing_alerts = json.load(f)
        except json.JSONDecodeError:
            print(f"[!] Failed to decode existing alerts from {filename}. Overwriting with new alerts.")
            existing_alerts = []    

    # 2. Map the NEW snapshot alerts (the ones that just arrived)
    # Incluimos la regla para diferenciar si un mismo proceso dispara alertas distintas
    new_snapshot_keys = {(alert['pid'], alert['name'], alert['rule']) for alert in alerts}

    # 3. Update status of historical alerts
    for alert in existing_alerts:
        alert_key = (alert['pid'], alert['name'], alert['rule'])
        if alert_key in new_snapshot_keys:
            alert['status'] = 'RUNNING'
        else:
            alert['status'] = 'TERMINATED'  

    # 4. Map what we already have in the history to avoid duplicate insertions
    existing_keys = {(alert['pid'], alert['name'], alert['rule']) for alert in existing_alerts}

    # 5. Append new alerts that are not already in the history
    for alert in alerts:
        alert_key = (alert['pid'], alert['name'], alert['rule'])
        if alert_key not in existing_keys:
            alert['status'] = 'RUNNING'
            alert['timestamp'] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            existing_alerts.insert(0, alert)  # Insert new alerts at the top

    # 6. Save everything back to disk
    try:
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(existing_alerts, f, indent=4)
        print(f"[*] Alerts saved to {filename}. Total alerts in history: {len(existing_alerts)}")
    except Exception as e:
        print(f"[!] Failed to save alerts to {filename}: {e}")

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

    # Run Rule 6: Reverse Shell Detection
    alerts.extend(check_reverse_shell(data))

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