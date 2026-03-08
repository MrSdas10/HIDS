"""
log_monitor.py - SSH Log Monitoring Module
Monitors /var/log/auth.log for failed SSH login attempts,
which may indicate brute-force attacks.
"""

import time
import os

from utils import write_alert

# Path to the SSH authentication log (Linux)
AUTH_LOG = "/var/log/auth.log"


def monitor_logs():
    """
    Continuously tail /var/log/auth.log and detect failed SSH login attempts.
    Uses a file seek approach to only read new lines as they are appended.
    This function is designed to run in its own thread.
    """
    print("[INFO] SSH log monitor started.")

    # Verify log file exists
    if not os.path.exists(AUTH_LOG):
        print(f"[WARNING] Log file not found: {AUTH_LOG}")
        print("[WARNING] SSH monitoring requires Linux with /var/log/auth.log.")
        print("[WARNING] SSH log monitor will retry every 30 seconds...")
        while not os.path.exists(AUTH_LOG):
            time.sleep(30)

    try:
        with open(AUTH_LOG, "r") as log_file:
            # Move to the end of the file to only read new entries
            log_file.seek(0, 2)

            while True:
                line = log_file.readline()
                if line:
                    # Detect failed SSH password attempts
                    if "Failed password" in line:
                        write_alert(
                            f"[ALERT] Failed SSH login attempt detected: "
                            f"{line.strip()}"
                        )
                else:
                    # No new lines — wait before checking again
                    time.sleep(1)

    except PermissionError:
        print(f"[ERROR] Permission denied reading {AUTH_LOG}.")
        print("[ERROR] Run with sudo: sudo python3 src/main.py")
    except (IOError, OSError) as e:
        print(f"[ERROR] Could not monitor log file: {e}")
