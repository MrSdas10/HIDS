"""
utils.py - Utility functions for Python HIDS
Provides hashing, baseline management, and alert logging.
"""

import hashlib
import json
import os
from datetime import datetime

# Path constants
BASELINE_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "baseline.json")
ALERT_LOG = os.path.join(os.path.dirname(os.path.dirname(__file__)), "alerts.log")


def hash_file(filepath):
    """
    Generate a SHA256 hash for a given file.
    Reads the file in chunks to handle large files efficiently.
    Returns the hex digest string, or None if the file cannot be read.
    """
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (IOError, OSError) as e:
        print(f"[ERROR] Could not read file {filepath}: {e}")
        return None


def save_baseline(baseline_dict):
    """
    Save file hash baseline to baseline.json.
    baseline_dict: {filepath: sha256_hash, ...}
    """
    try:
        with open(BASELINE_FILE, "w") as f:
            json.dump(baseline_dict, f, indent=4)
        print(f"[INFO] Baseline saved to {BASELINE_FILE}")
    except (IOError, OSError) as e:
        print(f"[ERROR] Could not save baseline: {e}")


def load_baseline():
    """
    Load file hash baseline from baseline.json.
    Returns a dict of {filepath: sha256_hash} or empty dict if not found.
    """
    if not os.path.exists(BASELINE_FILE):
        print("[INFO] No baseline file found. A new one will be created.")
        return {}
    try:
        with open(BASELINE_FILE, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, IOError) as e:
        print(f"[ERROR] Could not load baseline: {e}")
        return {}


def write_alert(message):
    """
    Write an alert message to the console and append it to alerts.log.
    Each alert is timestamped for forensic traceability.
    """
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_line = f"[{timestamp}] {message}"

    # Print to console
    print(alert_line)

    # Append to alerts.log
    try:
        with open(ALERT_LOG, "a") as f:
            f.write(alert_line + "\n")
    except (IOError, OSError) as e:
        print(f"[ERROR] Could not write to alert log: {e}")


def describe_alert(alert_type):
    """
    Return a beginner-friendly explanation for a given alert type.

    Args:
        alert_type (str): Examples: "brute_force", "file_change",
                          "privilege_escalation"

    Returns:
        dict: {
            "explanation": str,
            "risk_level": "Low" | "Medium" | "High",
            "suggested_mitigation": str
        }
    """
    alert_map = {
        "brute_force": {
            "explanation": (
                "Many login attempts were made in a short time. "
                "This may mean someone is trying to guess a password."
            ),
            "risk_level": "High",
            "suggested_mitigation": (
                "Block the source IP, enable account lockout or fail2ban, "
                "and use strong passwords with MFA."
            ),
        },
        "file_change": {
            "explanation": (
                "A monitored file was changed, deleted, or a new file appeared. "
                "This could be normal maintenance or unauthorized tampering."
            ),
            "risk_level": "Medium",
            "suggested_mitigation": (
                "Check who changed the file, compare it with a trusted backup, "
                "and restore it if the change is suspicious."
            ),
        },
        "privilege_escalation": {
            "explanation": (
                "A process or user may have gained higher permissions than expected, "
                "such as root/admin access."
            ),
            "risk_level": "High",
            "suggested_mitigation": (
                "Review recent sudo/admin activity, terminate unknown privileged "
                "processes, rotate credentials, and patch vulnerable software."
            ),
        },
    }

    normalized = (alert_type or "").strip().lower()
    if normalized in alert_map:
        return alert_map[normalized]

    return {
        "explanation": "This alert type is not recognized yet.",
        "risk_level": "Low",
        "suggested_mitigation": (
            "Collect more logs, verify if activity is expected, and add a "
            "specific rule for this alert type."
        ),
    }
