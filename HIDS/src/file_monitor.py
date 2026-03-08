"""
file_monitor.py - File Integrity Monitoring Module
Monitors the 'monitored/' directory for file modifications and deletions
by comparing current file hashes against a stored baseline.
"""

import os
import time

from utils import hash_file, save_baseline, load_baseline, write_alert

# Directory to monitor (relative to project root)
MONITORED_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "monitored")


def create_baseline():
    """
    Scan all files in the monitored directory and create a baseline
    of SHA256 hashes. Saves the result to baseline.json.
    """
    baseline = {}

    if not os.path.exists(MONITORED_DIR):
        os.makedirs(MONITORED_DIR)
        print(f"[INFO] Created monitored directory: {MONITORED_DIR}")

    for filename in os.listdir(MONITORED_DIR):
        filepath = os.path.join(MONITORED_DIR, filename)
        if os.path.isfile(filepath):
            file_hash = hash_file(filepath)
            if file_hash:
                baseline[filepath] = file_hash

    save_baseline(baseline)
    print(f"[INFO] Baseline created with {len(baseline)} file(s).")
    return baseline


def check_integrity():
    """
    Compare current file hashes against the stored baseline.
    Detects:
      - Modified files (hash mismatch)
      - Deleted files (file in baseline but missing on disk)
      - New files (file on disk but not in baseline)
    """
    baseline = load_baseline()

    if not baseline:
        print("[WARNING] No baseline found. Run create_baseline() first.")
        return

    # Check existing baseline entries for modifications or deletions
    for filepath, stored_hash in baseline.items():
        if not os.path.exists(filepath):
            write_alert(f"[ALERT] File DELETED: {filepath}")
        else:
            current_hash = hash_file(filepath)
            if current_hash and current_hash != stored_hash:
                write_alert(f"[ALERT] File MODIFIED detected: {filepath}")

    # Check for new files not in the baseline
    if os.path.exists(MONITORED_DIR):
        for filename in os.listdir(MONITORED_DIR):
            filepath = os.path.join(MONITORED_DIR, filename)
            if os.path.isfile(filepath) and filepath not in baseline:
                write_alert(f"[ALERT] New file detected (not in baseline): {filepath}")


def file_monitor_loop(interval=5):
    """
    Continuously monitor file integrity at a given interval (seconds).
    This function is designed to run in its own thread.
    """
    print(f"[INFO] File integrity monitor started (interval: {interval}s)")
    while True:
        check_integrity()
        time.sleep(interval)
