import psutil
import datetime

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

            process_list.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Skip processes that no longer exist or we don't have access to
            continue
        
    return process_list

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
        # memory_info gives rss (Resident Set Size), which is the actual RAM used
        ram_mb = p['memory_info'].rss / (1024 * 1024) if p['memory_info'] else 0
        print(f"CPU: {p['cpu_percent']}% | RAM: {ram_mb:.2f} MB")
        
        print("Network Connections:")
        for conn in p['connections']:
            print(f"  -> {conn['local_address']} maps to {conn['remote_address']} [{conn['status']}]")
        print("-" * 70)