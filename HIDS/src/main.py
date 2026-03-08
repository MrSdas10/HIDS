"""
main.py - Python Host Intrusion Detection System (HIDS)
Entry point that initializes all monitoring modules and runs
them concurrently using threads.

Usage:
    sudo python3 src/main.py

Modules:
    - File Integrity Monitor  (every 5 seconds)
    - SSH Log Monitor         (continuous tailing)
    - Process Monitor         (every 10 seconds)
"""

import threading
import sys
import os
import time

# Ensure the src/ directory is in the Python path
sys.path.insert(0, os.path.dirname(__file__))

from file_monitor import create_baseline, file_monitor_loop
from log_monitor import monitor_logs
from process_monitor import monitor_processes

BANNER = """
============================================================
   Python Host Intrusion Detection System (HIDS)
   Lightweight Linux Security Monitoring Tool
============================================================
   Modules:
     [1] File Integrity Monitor
     [2] SSH Brute-Force Log Monitor
     [3] Suspicious Process Monitor
============================================================
"""


def main():
    print(BANNER)

    # Step 1: Create initial file integrity baseline
    print("[*] Initializing file integrity baseline...")
    create_baseline()
    print()

    # Step 2: Define monitoring threads
    threads = [
        threading.Thread(
            target=file_monitor_loop,
            args=(5,),
            name="FileMonitor",
            daemon=True,
        ),
        threading.Thread(
            target=monitor_logs,
            name="SSHLogMonitor",
            daemon=True,
        ),
        threading.Thread(
            target=monitor_processes,
            name="ProcessMonitor",
            daemon=True,
        ),
    ]

    # Step 3: Start all monitoring threads
    print("[*] Starting monitoring threads...\n")
    for t in threads:
        t.start()
        print(f"    [+] {t.name} thread started.")

    print("\n[*] HIDS is now running. Press Ctrl+C to stop.\n")

    # Step 4: Keep the main thread alive and monitor thread health
    try:
        while True:
            for t in threads:
                if not t.is_alive():
                    print(f"[ERROR] {t.name} thread has stopped unexpectedly!")
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Shutting down HIDS. Goodbye.")
        sys.exit(0)


if __name__ == "__main__":
    main()
