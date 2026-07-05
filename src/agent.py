import psutil
import datetime
import os
import json

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

def collect_running_processes():
    """
    Captures current running processes with high resource efficiency.
    We only fetch the exact attributes we need to save memory and CPU.
    """
    process_list = []
    
    # Optimization: Map network connections first to cross-reference efficiently
    network_map = get_network_connections()
    
    # Efficient batching: passing attributes directly avoids making individual OS calls
    for proc in psutil.process_iter(['pid', 'name', 'ppid', 'username', 'cpu_percent', 'memory_info', 'exe', 'create_time']):
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

            process_list.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Skip processes that no longer exist or we don't have access to
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
    print("[*] Starting miniEDR telemetry collection test...")
    snapshot = collect_running_processes()
    print(f"[*] Successfully captured {len(snapshot)} processes with performance metrics.")

    # Filter processes that have active network connections
    processes_with_net = [p for p in snapshot if p['connections']]
    print(f"[*] Found {len(processes_with_net)} processes with active network connections.\n")

    # Let's print a sample of the first 3 processes with network data to inspect the telemetry
    print("[*] Telemetry Inspection Sample (First 3 processes with network):")
    print("=" * 70)
    
    for p in processes_with_net[:3]:
        print(f"PID: {p['pid']} | Name: {p['name']} | User: {p['username']}")
        print(f"Path: {p['exe']}")
        print(f"Timestamp: {p['timestamp']}")
        
        print(f"CPU: {p['cpu_percent']}% | RAM: {p['memory_usage_mb']} MB")
        
        print("Network Connections:")
        for conn in p['connections']:
            print(f"  -> {conn['local_address']} maps to {conn['remote_address']} [{conn['status']}]")
        print("-" * 70)
    # Save the captured data to disk
    save_telemetry_to_disk(snapshot)