import psutil
import datetime

def collect_running_processes():
    """
    Captures current running processes with high resource efficiency.
    We only fetch the exact attributes we need to save memory and CPU.
    """
    process_list = []
    # Efficient batching: passing attributes directly avoids making individual 
    # OS calls for each process property (like proc.name()), drastically reducing CPU usage.
    for proc in psutil.process_iter(['pid','name','ppid','username','cpu_percent','memory_info','exe','create_time']):
        try:
            # Extract basic info safely as a dictionary
            info = proc.info
            #timestamp
            info['timestamp'] = datetime.datetime.now().isoformat()

            process_list.append(info)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            # Skip processes that no longer exist or we don't have access to
            continue
        
    return process_list

if __name__ == "__main__":
    print("[*] Starting miniEDR telemetry collection test...")
    snapshot = collect_running_processes()
    print(f"[*] Successfully captured {len(snapshot)} processes with performance metrics.")