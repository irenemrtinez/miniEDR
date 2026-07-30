import hashlib
from datetime import datetime
import os
from pathlib import Path

from flask import json
from prevention_policies import read_policies
# Target extensiones commonly associated with execution vectors
TARGET_EXTENSIONS = {".exe", ".dll", ".bat", ".cmd", ".vbs", ".js", ".ps1", ".scr", ".jar", ".py", ".sh", ".src", ".bin", ".com", ".cpl", ".msc", ".hta", ".wsf", ".gadget"}

def calculate_hash(file_path):
    """
    Reads a file in binary chunks to calculate both MD5 and SHA-256 hashes
    without overloading host memory.
    """
    path_obj = Path(file_path)
    
    # Check if the file is empty or a Windows execution alias (0 bytes)
    try:
        if path_obj.stat().st_size == 0:
            return None, None
    except Exception:
        return None, None
    
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()

    try:
        with open(file_path, "rb") as f:
            # read in 4KB chunks
            for byte_block in iter(lambda: f.read(4096), b""):
                md5_hash.update(byte_block)
                sha256_hash.update(byte_block)
            return md5_hash.hexdigest(), sha256_hash.hexdigest()
    
    except PermissionError:
        # Silently log or handle restricted access without console clutter
        return None, None
    except OSError as e:
        # Handles [Errno 22] for UWP Virtual Execution Aliases smoothly
        return None, None
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None, None
    
def scan_directory_executables(directory):
    """
    Scans a specific directory, gathers metadata for executable files,
    and prepares a structured payload optimized for future VirusTotal lookup.
    """
    policies = read_policies()
    visibility = policies.get("visibility_controls", {})
    if not visibility.get("temp_directory_monitoring", True):
        print("[*] Temp Directory Monitoring disabled by policy. Skipping scan.")
        return []

    scanned_files = []
    path = Path(directory)

    if not path.exists() or not path.is_dir():
        print(f"Directory {directory} does not exist or is not a directory.")
        return scanned_files
    
    # files in the directory
    for file_entry in path.rglob("*"): # Recursive scan
        try:
            if file_entry.is_file() and file_entry.suffix.lower() in TARGET_EXTENSIONS:
                file_stats = file_entry.stat()

                # extract timestamps 
                creation_time = datetime.fromtimestamp(file_stats.st_ctime).strftime('%Y-%m-%d %H:%M:%S')
                modification_time = datetime.fromtimestamp(file_stats.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

                #calculate hashes
                md5, sha256 = calculate_hash(file_entry)

                if sha256 is None:
                    continue  # Skip files that couldn't be hashed

                scanned_files.append({
                    "name": file_entry.name,
                    "path": str(file_entry.absolute()),
                    "extension": file_entry.suffix.lower(),
                    "size_bytes": file_stats.st_size,
                    "created_at": creation_time,
                    "modified_at": modification_time,
                    "md5": md5,
                    "sha256": sha256,
                    "vt_scanned": False, # Flag to orchestrate your future VirusTotal integration
                    "vt_positives": 0
                })
        except Exception as e:
            print(f"Error processing file {file_entry}: {e}")
            continue

    return scanned_files

def save_files_to_disk(new_files,output_file="data/files_telemetry.json"):
    """
    Loads existing file telemetry from disk, merges new items by preventing
    SHA-256 duplication, and saves the comprehensive index back to disk.
    """
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    existing_files = []
    if os.path.exists(output_file):
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                existing_files = json.load(f)
        except Exception as e:
            print(f"[!] Failed to load existing file telemetry: {e}")
            existing_files = []
    
    #Map existing files by SHA-256 for quick deduplication 
    existing_hashes = {f['sha256'] for f in existing_files}
    
    #counter for tracking newly added files
    added_count = 0
    for file_data in new_files:
        if file_data['sha256'] not in existing_hashes:
            existing_files.append(file_data)
            existing_hashes.add(file_data['sha256'])
            added_count += 1

    # Write the updated inventory back to the JSON file
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(existing_files, f, indent=4)
        
    print(f"[+] File database updated. Added {added_count} new unique files. Total indexed: {len(existing_files)}")
   

#Quick standlone test execution context
if __name__ == "__main__":
    print("[*] Starting file analyzer...")
    # Example scanning a local user temporary folder or downloads folder
    user_downloads = os.path.expanduser("~/Downloads")

    # 1. Scan the environment
    detected_assets = scan_directory_executables(user_downloads)
    print(f"[+] Extracted raw telemetry for {len(detected_assets)} executable files.")
    # 2. Persist to data/files_telemetry.json
    save_files_to_disk(detected_assets)

    