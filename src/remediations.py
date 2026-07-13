import os
import shutil #copy, move, etc
from cryptography.fernet import Fernet #symmetric encryption AES-256

# Configuration of the quarantine directory
# Storing isolated assets inside a dedicated, restricted hidden folder
QUARANTINE_DIR = os.path.abspath(".miniEDR_quarantine")
KEY_FILE = os.path.abspath(".miniEDR_quarantine/vault.key")

def _get_or_create_key():
    """
    Guarantees the existence of a secure symmetric cryptographic key.
    Enforces OS-level strict Access Control Lists (ACLs).
    """
    if not os.path.exists(QUARANTINE_DIR): # creates the quarantine folder if it doesn't exist
        os.makedirs(QUARANTINE_DIR, mode=0o700)  # owner has full access (rwx), others have no access
    
    # Enforces Windows-specific hidden attributes via OS API shells
        if os.name == 'nt':
            try:
                import subprocess
                subprocess.run(['attrib', '+h', QUARANTINE_DIR], check=True)
            except Exception as e:
                print(f"[!] Failed to set Windows hidden attribute: {e}")

    if os.path.exists(KEY_FILE): # checks if the key file already exists
        with open(KEY_FILE, "rb") as f: # reads the existing key from the file. Necessary to fetch raw cryptographic bytes without string decoding
            return f.read()
    else:
        key = Fernet.generate_key() # generates a new symmetric key for encryption/decryption AES-256 using Fernet (which is built on AES in CBC mode with HMAC for integrity)
        with open(KEY_FILE, "wb") as f: # 'wb' stands for Write Binary. Writes raw bytes directly to disk
            f.write(key)
        os.chmod(KEY_FILE, 0o600) # Hardening: 0o600 grants Read/Write only to the owner. Prevents other users from stealing the key
        return key

def delete_file_from_disk(file_path):
    """
    Removes a malicious file from the operating system.
    Returns a tuple: (success: bool, message: str)
    """
    try:
        if not file_path:
            return False, "No file path provided."

        if not os.path.exists(file_path):
            # If the file is already gone, we consider the goal achieved
            return True, f"File {file_path} not found on disk (it might have been already removed)."
        
        #delete the file
        os.remove(file_path)
        print(f"[+] Successfully deleted file: {file_path}")
        return True, f"Successfully deleted file: {file_path}"
        
    except PermissionError:
        return False, f"Permission denied. Elevated privileges might be required to delete {file_path}."
    except Exception as e:
        return False, f"Failed to delete file: {str(e)}" 
    
def quarantine_file(file_path, alert_id):
    """
    1. Reads raw threat payload using binary streams ('rb').
    2. Encrypts payload via AES-256 to ensure 'Security At-Rest'.
    3. Safely stores it in a hidden sandbox directory changing extension to '.vir'.
    4. Strips execution flags using strict Unix file permissions.
    """
    try:
        if not file_path:
            return False, "No file path provided."

        if not os.path.exists(file_path):
            return False, f"File {file_path} not found on disk."
        
        key = _get_or_create_key()
        fernet = Fernet(key)

        # 1. Ingest the file in binary mode to avoid encoding issues
        with open(file_path, "rb") as f:    
           original_data = f.read()
        
        # 2. Encrypt the raw bytes using AES-256 (Fernet)
        encrypted_data = fernet.encrypt(original_data)

        # 3. Create a unique quarentine filename to avoid collisions
        safe_filename = f"malware_{alert_id}.vir"
        dest_path = os.path.join(QUARANTINE_DIR, safe_filename)

        # 4. Flush the encrypted payload to the secure quarantine directory
        with open(dest_path, "wb") as f:
            f.write(encrypted_data)
        
        # 5. Harden the quarantined file: Remove execution permissions
        os.chmod(dest_path, 0o400)  # Read-only for owner, no access for others

        # 6. Purge the original file from the infected path
        os.remove(file_path)

        return True, safe_filename
    
    except PermissionError:
        return False, f"Permission denied. Elevated privileges might be required to quarantine {file_path}."    
    except Exception as e:
        return False, f"Failed to quarantine file: {str(e)}"
    
def restore_file_from_quarantine(quarantined_filename, restore_path):
    """
    1. Decrypts the quarantined file using the stored symmetric key.
    2. Restores it to a user-defined safe location.
    3. Ensures the restored file has no execution permissions by default.
    """
    try:
        q_path = os.path.join(QUARANTINE_DIR, quarantined_filename)
        if not os.path.exists(q_path):
            return False, f"Quarantined file {quarantined_filename} not found."
        
        key= _get_or_create_key()
        fernet = Fernet(key)

        #1. Read the encrypted payload
        with open(q_path, "rb") as f:
            encrypted_data = f.read()

        #2. Decrypt the payload
        decrypted_data = fernet.decrypt(encrypted_data)

        #3. Write the decrypted file to the restore path
        with open(restore_path, "wb") as f:
            f.write(decrypted_data)
        
        #4. CLEAN UP HARDENING: Grant write permissions back to the file so OS can delete it
        os.chmod(q_path, 0o600) # Read/Write for owner

        #5. clean up the quarantined file after successful restoration
        os.remove(q_path)
        return True, f"File restored successfully to {restore_path}."
    
    except PermissionError:
        return False, f"Permission denied. Elevated privileges might be required to restore {quarantined_filename}."
    except Exception as e:
        return False, f"Failed to restore file: {str(e)}"

        