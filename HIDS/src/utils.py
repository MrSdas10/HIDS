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
