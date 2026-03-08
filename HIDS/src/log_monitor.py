"""
log_monitor.py - SSH Log Monitoring Module
Monitors /var/log/auth.log for failed SSH login attempts,
which may indicate brute-force attacks.
"""

import time
import os

from utils import write_alert

# Possible SSH authentication log paths (varies by distro)
AUTH_LOG_PATHS = [
    "/var/log/auth.log",     # Ubuntu, Debian, Kali (with rsyslog)
    "/var/log/syslog",       # Fallback on some distros
    "/var/log/secure",       # CentOS, RHEL, Fedora
]


def find_auth_log():
    """Find the first available SSH log file on the system."""
    for path in AUTH_LOG_PATHS:
        if os.path.exists(path):
            return path
    return None


def monitor_logs():
    """
    Continuously tail the SSH authentication log and detect failed login attempts.
    Automatically detects the correct log file for the distro.
    This function is designed to run in its own thread.
    """
    print("[INFO] SSH log monitor started.")

    # Find the correct log file
    auth_log = find_auth_log()

    if not auth_log:
        print("[WARNING] No SSH log file found.")
        print("[WARNING] On Kali Linux, install rsyslog if auth.log is missing:")
        print("          sudo apt install rsyslog && sudo systemctl enable rsyslog --now")
        print("[WARNING] SSH log monitor will retry every 15 seconds...")
        while not auth_log:
            time.sleep(15)
            auth_log = find_auth_log()

    print(f"[INFO] Monitoring SSH log: {auth_log}")

    try:
        with open(auth_log, "r") as log_file:
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
        print(f"[ERROR] Permission denied reading {auth_log}.")
        print("[ERROR] Run with sudo: sudo python3 src/main.py")
    except (IOError, OSError) as e:
        print(f"[ERROR] Could not monitor log file: {e}")
