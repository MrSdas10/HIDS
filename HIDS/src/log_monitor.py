"""
log_monitor.py - SSH Log Monitoring Module
Monitors /var/log/auth.log for failed SSH login attempts,
which may indicate brute-force attacks.
"""

import time
import os

from utils import write_alert

# Primary SSH authentication log path
AUTH_LOG = "/var/log/auth.log"


def ensure_auth_log():
    """
    Ensure /var/log/auth.log exists.
    On Kali Linux, rsyslog may not be installed by default,
    so auth.log may not exist. We create it for manual testing.
    """
    if not os.path.exists(AUTH_LOG):
        print(f"[WARNING] {AUTH_LOG} does not exist.")
        print("[WARNING] Creating it for manual testing...")
        print("[WARNING] For real SSH monitoring, install rsyslog:")
        print("          sudo apt install rsyslog && sudo systemctl enable rsyslog --now")
        try:
            with open(AUTH_LOG, "w") as f:
                f.write("")
            print(f"[INFO] Created {AUTH_LOG}")
        except PermissionError:
            print(f"[ERROR] Cannot create {AUTH_LOG}. Run with sudo.")
            return False
        except (IOError, OSError) as e:
            print(f"[ERROR] Cannot create {AUTH_LOG}: {e}")
            return False
    return True


def monitor_logs():
    """
    Continuously tail /var/log/auth.log and detect failed SSH login attempts.
    Creates the log file if it doesn't exist (for manual testing on Kali).
    This function is designed to run in its own thread.
    """
    print("[INFO] SSH log monitor started.")

    if not ensure_auth_log():
        print("[ERROR] SSH log monitor cannot start. Exiting thread.")
        return

    print(f"[INFO] Monitoring SSH log: {AUTH_LOG}")
    print(f"[INFO] To test, run in another terminal:")
    print(f'        echo "Mar  8 14:35:00 kali sshd[1234]: Failed password for testuser from 192.168.1.100 port 22 ssh2" | sudo tee -a {AUTH_LOG}')

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
                    # Handle log rotation: if file was truncated, re-seek
                    current_pos = log_file.tell()
                    file_size = os.path.getsize(AUTH_LOG)
                    if file_size < current_pos:
                        log_file.seek(0)
                    # No new lines — wait before checking again
                    time.sleep(1)

    except PermissionError:
        print(f"[ERROR] Permission denied reading {AUTH_LOG}.")
        print("[ERROR] Run with sudo: sudo python3 src/main.py")
    except (IOError, OSError) as e:
        print(f"[ERROR] Could not monitor log file: {e}")
