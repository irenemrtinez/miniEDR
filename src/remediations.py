import os

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