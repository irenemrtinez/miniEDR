import os
import json
from flask import Blueprint, render_template, request, jsonify

# Blueprint for modularizing prevention policies and settings
prevention_bp = Blueprint('prevention', __name__)

POLICIES_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data', 'policies.json')

def read_policies():
    """Reads the policies JSON file, returning default fallback values if missing or unreadable."""
    default_policies = {
        "visibility_controls": {
            "extended_process_telemetry": True,
            "temp_directory_monitoring": True,
            "virustotal_intelligence": True
        },
        "prevention_policies": {
            "auto_quarantine": { "threshold": "disabled" },
            "auto_process_kill": { "threshold": "disabled" }
        }
    }
    
    if not os.path.exists(POLICIES_FILE):
        return default_policies
        
    try:
        with open(POLICIES_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data if isinstance(data, dict) else default_policies
    except Exception as e:
        print(f"[!] Error reading {POLICIES_FILE}: {e}")
        return default_policies

@prevention_bp.route('/prevention')
def prevention_page():
    """Renders the Policy & Telemetry Settings view."""
    policies = read_policies()
    return render_template('prevention.html', policies=policies)

@prevention_bp.route('/api/policies/save', methods=['POST'])
def save_policies():
    """API Endpoint to receive and persist configuration changes from the frontend."""
    try:
        new_policies = request.get_json()
        if not new_policies:
            return jsonify({"status": "error", "message": "Invalid JSON payload"}), 400

        os.makedirs(os.path.dirname(POLICIES_FILE), exist_ok=True)
        with open(POLICIES_FILE, 'w', encoding='utf-8') as f:
            json.dump(new_policies, f, indent=4)

        print("[+] Prevention policies updated successfully.")
        return jsonify({"status": "success", "message": "Policies updated successfully"}), 200

    except Exception as e:
        print(f"[!] Error saving policies: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500