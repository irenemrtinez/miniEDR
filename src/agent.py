import psutil
import datetime
import os
import json
import time

def get_network_connections():
    """
    Fetches all system connections in a single OS call and maps them by PID.
    This optimization avoids querying each process individually.
    """
    connections_by_pid = {}
    try:
        # psutil.net_connections() gets everything at once
        for conn in psutil.net_connections(kind='inet'):
            if conn.pid:
                if conn.pid not in connections_by_pid:
                    connections_by_pid[conn.pid] = []

                connection_info = {
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "status": conn.status
                }
                connections_by_pid[conn.pid].append(connection_info)
    except (psutil.AccessDenied, psutil.NoSuchProcess):
        # If we can't access network connections, return empty dict safely
        pass
    return connections_by_pid

def collect_running_processes(extended=True):
    """
    Captures current running processes with high resource efficiency.
    We only fetch the exact attributes we need to save memory and CPU.
    """
    process_list = []
    
    # Optimization: Map network connections first to cross-reference efficiently
    network_map = get_network_connections()

    attributes = ['pid', 'ppid', 'name', 'username', 'cpu_percent', 'memory_info', 'exe', 'create_time', 'cmdline']
    if extended:
        attributes.append('cmdline')
    # Efficient batching: passing attributes directly avoids making individual OS calls
    for proc in psutil.process_iter(attributes):
        try:
            # Extract basic info safely as a dictionary
            info = proc.info
            
            # Timestamp enrichment for temporal analysis
            info['timestamp'] = datetime.datetime.now().isoformat()

            # Telemetry enrichment: Inject network data using the PID as the key
            info['connections'] = network_map.get(info['pid'], [])

            # Convert memory from bytes to Megabytes
            if info['memory_info']:
                info['memory_usage_mb'] = round(info['memory_info'].rss / (1024 * 1024), 2)
            else:
                info['memory_usage_mb'] = 0.0
            
            # Delete the complex object so it doesn't crash the JSON writer later
            del info['memory_info']

            # --- EXTENDED PROCESS TELEMETRY ENRICHMENT ---
            if extended:
                # 1. Command-line Arguments
                # Convert list of arguments into a unified execution command string
                cmdline_list = info.get('cmdline')
                if cmdline_list and isinstance(cmdline_list, list):
                    info['cmdline'] = " ".join(cmdline_list)
                else:
                    info['cmdline'] = "N/A"

                # 2. Parent Process Details (Parent-Child Process Tree)
                ppid = info.get('ppid')
                if ppid and ppid > 0:
                    try:
                        parent_proc = psutil.Process(ppid)
                        info['parent_name'] = parent_proc.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        info['parent_name'] = "Unknown / Terminated"
                else:
                    info['parent_name'] = "System / Root"

                # 3. Loaded Dynamic Link Libraries (DLLs / Shared Modules)
                # Fetching loaded memory maps safely to prevent permission crashes
                try:
                    # Top 10 loaded modules/DLLs to prevent bloated JSON payloads
                    memory_maps = proc.memory_maps()
                    info['loaded_dlls'] = [m.path for m in memory_maps if m.path.endswith('.dll')][:10]
                except (psutil.AccessDenied, psutil.NoSuchProcess, NotImplementedError, AttributeError):
                    info['loaded_dlls'] = []

            process_list.append(info)

        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
        
    return process_list

def save_telemetry_to_disk(snapshot, filename="data/telemetry.json"):
    """
    Saves the normalized telemetry snapshot into a structured JSON file.
    Ensures the target folder exists before writing to prevent OS crashes.
    """

    #  create the 'data' directory if it doesn't exist yet.
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    
    try:
        #safely handles opening and closing the file.
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(snapshot, f, indent=4)
        print(f"[*] Telemetry snapshot saved to {filename}")

    except Exception as e:
        print(f"[!] Failed to save telemetry snapshot: {e}")

if __name__ == "__main__":
    # This interval defines how often the EDR takes a snapshot (in seconds)
    MONITOR_INTERVAL = 15
    
    print(f"[*] Starting miniEDR telemetry engine. Monitoring every {MONITOR_INTERVAL} seconds...")
    print("[*] Press Ctrl+C to stop the agent safely.\n")

    try:
        while True:
            print(f"[{datetime.datetime.now().strftime('%H:%M:%S')}] Gathering new telemetry snapshot...")
            
            # 1. Collect the data
            snapshot = collect_running_processes()
            
            # 2. Overwrite the JSON file with fresh data
            save_telemetry_to_disk(snapshot)
            
            # 3. Efficiency break: Sleep to keep CPU usage close to 0%
            time.sleep(MONITOR_INTERVAL)
            
    except KeyboardInterrupt:
        #  catches Ctrl+C cleanly without showing ugly error traces
        print("\n[!] miniEDR Agent stopped safely by the user. Goodbye!")