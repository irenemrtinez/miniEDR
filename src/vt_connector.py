import os
import json
import requests

VT_API_KEY = "" # Replace with your actual VirusTotal API key
VT_BASE_URL = "https://www.virustotal.com/api/v3"

def check_file_hash_vt(sha256_hash):
    """
    Queries VirusTotal intelligence using a file's SHA256 hash to retrieve its reputation and analysis results.
    returns (is_known,positive_count) or (false,0) if not found
    """
    if not VT_API_KEY:
        print("[!] VirusTotal API key is not set. Skipping VT query.")
        return False, 0
    
    URL = f"{VT_BASE_URL}/files/{sha256_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    try:
        response = requests.get(URL, headers=headers)
        
        if response.status_code == 200:
            #file exists in VT database, parse the JSON response to get the positive count
            data = response.json()
            # Extract analysis detection metrics
            stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            positives = stats.get('malicious', 0)
            print(f"[+] Hash {sha256_hash[:10]}... FOUND. Malicious detections: {positives}")
            return True, positives
        
        elif response.status_code == 404:
            print(f"[*] Hash {sha256_hash[:10]}... NOT FOUND in VirusTotal database.")
            return False, 0
        else:
            print(f"[!] Error querying VirusTotal: {response.status_code} - {response.text}")
            return False, 0
        
    except Exception as e:
        print(f"[!] Exception occurred while querying VirusTotal: {e}")
        return False, 0
    
if __name__ == "__main__":
    print("[*] Starting VirusTotal hash check test...")

    TELEMETRY_FILE = "data/files_telemetry.json"
    if not os.path.exists(TELEMETRY_FILE):
        print(f"[!] Telemetry file {TELEMETRY_FILE} not found. Please run the file analyzer first.")
        exit()

    # 1. read the data base file
    with open(TELEMETRY_FILE, "r") as f:
        telemetry_data = json.load(f)

    # 2. search for the first file not scanned yet
    target_file = None
    #first search for eicar test file, if not found, then search for any unscanned file
    for file_entry in telemetry_data:
        if not file_entry.get("vt_scanned", False) and ("eicar" in file_entry["name"].lower() or "test_virus_total" in file_entry["name"].lower()):
            target_file = file_entry
            print("[*] ¡Eicar test file found in telemetry data! Proceeding to query VirusTotal...")
            break
    if not target_file:
        for file_entry in telemetry_data:
            if not file_entry.get("vt_scanned", False):
                target_file = file_entry
                break # break the loop once we find the first unscanned file
    
    if not target_file:
        print("[*] No unscanned files found in telemetry data. All files have been checked against VirusTotal.")
        exit()
    else:
        print(f"[*] Found unscanned file: {target_file['path']} with SHA256: {target_file['sha256']}")
    # 3. query VT for this file's hash
    found, positives = check_file_hash_vt(target_file['sha256'])
    # 4. check as scanned
    target_file["vt_scanned"] = True
    target_file["vt_positives"] = positives
    # 5. save the updated telemetry data back to disk
    with open(TELEMETRY_FILE, 'w', encoding='utf-8') as f:
            json.dump(telemetry_data, f, indent=4)
            
    print("[+] Updated local database for this file.")
