"""
process_monitor.py - Suspicious Process Monitoring Module
Detects processes running as root that are NOT in a trusted whitelist.
Flags unknown root processes as potential indicators of compromise.
"""

import time
import psutil

from utils import write_alert

# Whitelist of known safe root processes.
# Uses prefix matching — e.g. "python3" also matches "python3.11".
# Add legitimate system processes here to reduce false positives.
WHITELISTED_PREFIXES = [
    # Core system processes
    "systemd", "init", "kthreadd", "kworker", "ksoftirqd",
    "rcu_", "migration", "watchdog", "cpuhp", "netns",
    "khungtaskd", "oom_reaper", "kcompactd", "kdevtmpfs",
    "inet_frag_worker", "kauditd", "khugepaged", "kintegrityd",
    "kblockd", "blkcg_punt_bio", "tpm_dev_wq", "ata_sff",
    "md", "edac-poller", "devfreq_wq", "watchdogd", "pm_wq",
    "scsi_", "ext4", "jbd2",
    # System services
    "sshd", "cron", "rsyslogd", "networkd", "snapd",
    "dockerd", "containerd", "accounts-daemon", "polkitd",
    "dbus-daemon", "dbus-broker", "irqbalance", "multipathd",
    "bash", "sh", "dash", "zsh", "login", "agetty", "atd",
    "NetworkManager", "thermald", "udisksd",
    "unattended-upgr", "packagekitd",
    # Systemd services
    "(sd-pam)",
    # Auth & session
    "sudo", "su", "lightdm", "gdm", "sddm", "slim",
    # Display & desktop
    "Xorg", "Xwayland", "xfce4", "xfwm4", "xfdesktop",
    "xfsettingsd", "gnome-session", "gnome-shell", "plasmashell",
    # Audio & hardware
    "pulseaudio", "pipewire", "wireplumber", "colord",
    "rtkit-daemon", "upowerd",
    # Network & connectivity
    "ModemManager", "wpa_supplicant", "bluetoothd",
    "dhclient", "avahi-daemon",
    # Services
    "cupsd", "apache2", "nginx", "postgres", "mysql", "mariadbd",
    # Misc
    "panel-", "power-manager", "tumblerd", "gvfsd", "gvfs-",
    "at-spi", "dconf-service", "gpg-agent", "ssh-agent",
]


def is_whitelisted(proc_name):
    """Check if a process name matches any whitelisted prefix."""
    for prefix in WHITELISTED_PREFIXES:
        if proc_name.startswith(prefix):
            return True
    return False


def monitor_processes():
    """
    Scan running processes and flag any root-owned process that
    is not in the whitelist. Tracks already-alerted PIDs to avoid
    flooding the console with duplicate alerts.
    This function is designed to run in its own thread.
    """
    print("[INFO] Process monitor started.")
    # Track PIDs we've already alerted on to avoid duplicates
    alerted_pids = set()

    while True:
        current_pids = set()
        try:
            for proc in psutil.process_iter(["pid", "name", "username"]):
                try:
                    proc_info = proc.info
                    username = proc_info.get("username")
                    proc_name = proc_info.get("name")
                    pid = proc_info.get("pid")

                    if not proc_name or not username:
                        continue

                    # Only inspect root-owned processes
                    if username == "root" and not is_whitelisted(proc_name):
                        # Skip kernel threads (they have no cmdline)
                        try:
                            cmdline = proc.cmdline()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            cmdline = []
                        if cmdline and pid not in alerted_pids:
                            write_alert(
                                f"[WARNING] Suspicious root process detected: "
                                f"PID={pid} Name={proc_name} User={username}"
                            )
                            alerted_pids.add(pid)
                        current_pids.add(pid)

                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

        except Exception as e:
            print(f"[ERROR] Process monitoring error: {e}")

        # Clean up alerted PIDs that no longer exist
        alerted_pids = alerted_pids.intersection(current_pids)

        # Wait before next scan cycle
        time.sleep(10)
