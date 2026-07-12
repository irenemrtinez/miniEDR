from datetime import datetime
import os
import json
from dotenv import load_dotenv
import requests

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE_URL = "https://www.virustotal.com/api/v3"

def check_file_hash_vt(sha256_hash):
    """
    Queries VirusTotal using a file's SHA256 hash.
    Returns a dictionary with comprehensive threat intelligence metadata.
    """
    if not VT_API_KEY:
        print("[!] VirusTotal API key is not set. Skipping VT query.")
        return {"vt_status": "PENDING"}
    
    URL = f"{VT_BASE_URL}/files/{sha256_hash}"
    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }

    # Captured time when WE query the file for analysis
    current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    try:
        response = requests.get(URL, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            
            # Extract relevant 'Everyone' attributes requested
            stats = attributes.get('last_analysis_stats', {})
            malicious = stats.get('malicious', 0)
            
            # Calculate total engines used (e.g., 62) by summing analysis stats
            total_vendors = sum(stats.values()) if stats else 0
            
            # Determine the explicit EDR status based on findings
            status = "SUSPICIOUS" if malicious > 0 else "CLEAN"
            
            print(f"[+] Hash {sha256_hash[:10]}... FOUND. Status: {status} ({malicious}/{total_vendors})")
            
            return {
                "vt_status": status,
                "vt_positives": malicious,
                "vt_total_vendors": total_vendors,
                "vt_analyzed_at": current_time,
                "vt_first_submission": attributes.get('first_submission_date'),
                "vt_magic": attributes.get('magic'),
                "vt_alternative_names": attributes.get('names', [])[:3] # Keep top 3 alternative names
            }
        
        elif response.status_code == 404:
            print(f"[*] Hash {sha256_hash[:10]}... NOT FOUND in VirusTotal database.")
            return {
                "vt_status": "NOT_FOUND",
                "vt_positives": 0,
                "vt_total_vendors": 0,
                "vt_analyzed_at": current_time,
                "vt_first_submission": None,
                "vt_magic": "Unknown binary data",
                "vt_alternative_names": []
            }
        else:
            print(f"[!] Error querying VirusTotal: {response.status_code} - {response.text}")
            return {"vt_status": "PENDING"}
        
    except Exception as e:
        print(f"[!] Exception occurred while querying VirusTotal: {e}")
        return {"vt_status": "PENDING"}
    
if __name__ == "__main__":
    print("[*] Starting VirusTotal hash check test...")

    TELEMETRY_FILE = "data/files_telemetry.json"
    if not os.path.exists(TELEMETRY_FILE):
        print(f"[!] Telemetry file {TELEMETRY_FILE} not found. Please run the file analyzer first.")
        exit()

    # 1. Read the database file
    with open(TELEMETRY_FILE, "r", encoding="utf-8") as f:
        telemetry_data = json.load(f)

    # 2. Search for the first file not scanned yet
    target_file = None
    # First search for eicar test file, if not found, then search for any unscanned file
    for file_entry in telemetry_data:
        status = file_entry.get("vt_status", "PENDING")
        if (status == "PENDING" or not file_entry.get("vt_status")) and "maligno" in file_entry["name"].lower():
            target_file = file_entry
            print("[*] Target file 'maligno' prioritized in telemetry data! Proceeding to query VirusTotal...")
            break
            
    if not target_file:
        for file_entry in telemetry_data:
            if file_entry.get("vt_status", "PENDING") == "PENDING":
                target_file = file_entry
                break # Break the loop once we find the first unscanned file
    
    if not target_file:
        print("[*] No unscanned files found in telemetry data. All files have been checked against VirusTotal.")
        exit()
    else:
        print(f"[*] Found unscanned file: {target_file['path']} with SHA256: {target_file['sha256']}")
        
    # 3. Query VT for this file's hash (FIXED: Now receives the complete dictionary payload)
    vt_results = check_file_hash_vt(target_file['sha256'])
    
    # 4. Update the dictionary with the new structured metadata fields
    target_file.update(vt_results)
    
    # 5. Save the updated telemetry data back to disk
    with open(TELEMETRY_FILE, 'w', encoding='utf-8') as f:
        json.dump(telemetry_data, f, indent=4)
            
    print("[+] Updated local database for this file.")
