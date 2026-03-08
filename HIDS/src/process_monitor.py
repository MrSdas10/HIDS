"""
process_monitor.py - Suspicious Process Monitoring Module
Detects processes running as root that are NOT in a trusted whitelist.
Flags unknown root processes as potential indicators of compromise.
"""

import time
import psutil

from utils import write_alert

# Whitelist of known safe root processes.
# Add legitimate system processes here to reduce false positives.
WHITELISTED_PROCESSES = {
    # Core system processes
    "systemd",
    "init",
    "kthreadd",
    "sshd",
    "cron",
    "rsyslogd",
    "networkd",
    "snapd",
    "dockerd",
    "containerd",
    "accounts-daemon",
    "polkitd",
    "dbus-daemon",
    "irqbalance",
    "multipathd",
    "bash",
    "login",
    "agetty",
    "atd",
    "NetworkManager",
    "thermald",
    "udisksd",
    "unattended-upgr",
    "packagekitd",
    # Systemd services
    "systemd-journald",
    "systemd-udevd",
    "systemd-logind",
    "systemd-resolved",
    "systemd-timesyncd",
    "systemd-network",
    "systemd-oomd",
    # Auth & session
    "sudo",
    "su",
    "lightdm",
    "gdm",
    "gdm-session-wor",
    "sddm",
    # Display & desktop
    "Xorg",
    "Xwayland",
    "xfce4-session",
    "gnome-session-b",
    "plasmashell",
    # Audio & hardware
    "pulseaudio",
    "pipewire",
    "pipewire-pulse",
    "wireplumber",
    "colord",
    "rtkit-daemon",
    "upowerd",
    # Network & connectivity
    "ModemManager",
    "wpa_supplicant",
    "bluetoothd",
    "dhclient",
    "avahi-daemon",
    # Services
    "cupsd",
    "apache2",
    "postgres",
    "mysql",
    "mariadbd",
    # Kali-specific
    "xfdesktop",
    "xfwm4",
    "xfce4-panel",
    "xfsettingsd",
    "panel-plugins",
    "power-manager",
}


def monitor_processes():
    """
    Scan running processes and flag any root-owned process that
    is not in the whitelist. This function is designed to run
    in its own thread on a recurring interval.
    """
    print("[INFO] Process monitor started.")

    while True:
        try:
            for proc in psutil.process_iter(["pid", "name", "username"]):
                try:
                    proc_info = proc.info
                    username = proc_info.get("username")
                    proc_name = proc_info.get("name")
                    pid = proc_info.get("pid")

                    # Only inspect root-owned processes
                    if username == "root" and proc_name and proc_name not in WHITELISTED_PROCESSES:
                        # Skip kernel threads (they have no cmdline)
                        try:
                            cmdline = proc.cmdline()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            cmdline = []
                        if cmdline:
                            write_alert(
                                f"[WARNING] Suspicious root process detected: "
                                f"PID={pid} Name={proc_name} User={username}"
                            )

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Process ended or access denied — skip it
                    continue

        except Exception as e:
            print(f"[ERROR] Process monitoring error: {e}")

        # Wait before next scan cycle
        time.sleep(10)
