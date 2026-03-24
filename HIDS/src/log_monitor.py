"""
log_monitor.py - SSH Log Monitoring Module
Monitors /var/log/auth.log for SSH brute-force activity.

Detections:
    1) Multiple failed SSH attempts from the same IP within 2 minutes
    2) Successful SSH login after multiple failures from the same IP
"""

import os
import re
import ipaddress
import subprocess
import json
import shutil
import time
from collections import defaultdict, deque
from datetime import datetime

from utils import write_alert

# Primary SSH authentication log path
AUTH_LOG = "/var/log/auth.log"

# Detection tuning
WINDOW_SECONDS = 120
FAIL_THRESHOLD = 3
BAN_DURATION_SECONDS = 900

# Persistent blocked IP state file
BLOCKED_IPS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)),
    "blocked_ips.json",
)

# nftables defaults
NFT_FAMILY = "inet"
NFT_TABLE = "filter"
NFT_CHAIN = "input"

# Regex for IPv4 extraction from auth.log entries
IP_REGEX = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


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


def extract_ip(line):
    """Extract the first IPv4 address from a log line, if present."""
    match = IP_REGEX.search(line)
    return match.group(0) if match else None


def is_failed_ssh_attempt(line):
    """Return True if the line indicates a failed SSH authentication attempt."""
    return "sshd" in line and "Failed password" in line


def is_successful_ssh_login(line):
    """Return True if the line indicates a successful SSH authentication."""
    return "sshd" in line and "Accepted " in line


def prune_old_attempts(attempts_by_ip, ip, now_ts):
    """Keep only attempts in the rolling detection window for this IP."""
    attempts = attempts_by_ip[ip]
    while attempts and (now_ts - attempts[0]) > WINDOW_SECONDS:
        attempts.popleft()


def alert_bruteforce(ip, attempt_count):
    """Emit a brute-force alert."""
    write_alert(
        f"[ALERT] SSH_BRUTE_FORCE ip={ip} attempts={attempt_count} "
        f"window={WINDOW_SECONDS}s"
    )


def alert_success_after_failures(ip, attempt_count):
    """Emit a success-after-failures alert."""
    write_alert(
        f"[ALERT] SSH_SUCCESS_AFTER_FAILURES ip={ip} "
        f"previous_failures={attempt_count} window={WINDOW_SECONDS}s"
    )


def _run_cmd(cmd):
    """Run a system command and return CompletedProcess without raising."""
    try:
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
            timeout=5,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            args=cmd,
            returncode=1,
            stdout="",
            stderr="command timed out",
        )


def _format_command_error(result):
    """Extract an error message from command output."""
    return (result.stderr or result.stdout or "unknown error").strip()


def _detect_firewall_backend():
    """Auto-detect an available firewall backend."""
    if shutil.which("nft"):
        return "nft"
    if shutil.which("iptables") or shutil.which("ip6tables"):
        return "iptables"
    return None


def _ensure_nft_input_chain():
    """Check that the nftables input chain exists before adding rules."""
    result = _run_cmd(["nft", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_CHAIN])
    if result.returncode != 0:
        write_alert(
            "[ERROR] nftables input chain missing "
            f"({NFT_FAMILY} {NFT_TABLE} {NFT_CHAIN})."
        )
        return False
    return True


def _nft_rule_fragment(ip_obj):
    """Return the nft rule fragment for IPv4/IPv6 source matches."""
    if ip_obj.version == 6:
        return f"ip6 saddr {ip_obj.compressed} drop"
    return f"ip saddr {ip_obj.compressed} drop"


def _nft_is_blocked(ip_obj):
    """Check whether a matching nft drop rule already exists."""
    list_result = _run_cmd(["nft", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_CHAIN])
    if list_result.returncode != 0:
        write_alert(f"[ERROR] nft list failed: {_format_command_error(list_result)}")
        return False

    return _nft_rule_fragment(ip_obj) in list_result.stdout


def _nft_add_block(ip_obj):
    """Add nft drop rule for the source IP."""
    if not _ensure_nft_input_chain():
        return False

    if _nft_is_blocked(ip_obj):
        write_alert(f"[ACTION] IP_ALREADY_BLOCKED ip={ip_obj.compressed} via=nftables")
        return True

    cmd = [
        "nft",
        "add",
        "rule",
        NFT_FAMILY,
        NFT_TABLE,
        NFT_CHAIN,
    ] + _nft_rule_fragment(ip_obj).split()

    result = _run_cmd(cmd)
    if result.returncode != 0:
        write_alert(
            f"[ERROR] Failed to block ip={ip_obj.compressed} via nftables: "
            f"{_format_command_error(result)}"
        )
        return False

    write_alert(f"[ACTION] IP_BLOCKED ip={ip_obj.compressed} via=nftables")
    return True


def _nft_remove_block(ip_obj):
    """Remove matching nft drop rule(s) for the source IP."""
    if not _ensure_nft_input_chain():
        return False

    list_result = _run_cmd(
        ["nft", "-a", "list", "chain", NFT_FAMILY, NFT_TABLE, NFT_CHAIN]
    )
    if list_result.returncode != 0:
        write_alert(f"[ERROR] nft list failed: {_format_command_error(list_result)}")
        return False

    target = _nft_rule_fragment(ip_obj)
    handles = []
    for line in list_result.stdout.splitlines():
        if target in line and "# handle" in line:
            match = re.search(r"# handle (\d+)", line)
            if match:
                handles.append(match.group(1))

    if not handles:
        write_alert(f"[ACTION] IP_NOT_BLOCKED ip={ip_obj.compressed} via=nftables")
        return True

    success = True
    for handle in handles:
        delete_result = _run_cmd(
            [
                "nft",
                "delete",
                "rule",
                NFT_FAMILY,
                NFT_TABLE,
                NFT_CHAIN,
                "handle",
                handle,
            ]
        )
        if delete_result.returncode != 0:
            success = False
            write_alert(
                f"[ERROR] Failed to remove nft rule handle={handle} "
                f"ip={ip_obj.compressed}: {_format_command_error(delete_result)}"
            )

    if success:
        write_alert(f"[ACTION] IP_UNBLOCKED ip={ip_obj.compressed} via=nftables")
    return success


def _iptables_binary_for_ip(ip_obj):
    """Return the correct binary for IPv4/IPv6 iptables operations."""
    return "ip6tables" if ip_obj.version == 6 else "iptables"


def _iptables_add_block(ip_obj):
    """Add iptables/ip6tables drop rule for the source IP."""
    binary = _iptables_binary_for_ip(ip_obj)
    if not shutil.which(binary):
        write_alert(f"[ERROR] {binary} command not found. Cannot block IP.")
        return False

    ip = ip_obj.compressed
    exists_result = _run_cmd([binary, "-C", "INPUT", "-s", ip, "-j", "DROP"])
    if exists_result.returncode == 0:
        write_alert(f"[ACTION] IP_ALREADY_BLOCKED ip={ip} via={binary}")
        return True

    add_result = _run_cmd([binary, "-A", "INPUT", "-s", ip, "-j", "DROP"])
    if add_result.returncode != 0:
        write_alert(
            f"[ERROR] Failed to block ip={ip} via {binary}: "
            f"{_format_command_error(add_result)}"
        )
        return False

    write_alert(f"[ACTION] IP_BLOCKED ip={ip} via={binary}")
    return True


def _iptables_remove_block(ip_obj):
    """Remove iptables/ip6tables drop rule for the source IP if present."""
    binary = _iptables_binary_for_ip(ip_obj)
    if not shutil.which(binary):
        write_alert(f"[ERROR] {binary} command not found. Cannot unblock IP.")
        return False

    ip = ip_obj.compressed
    exists_result = _run_cmd([binary, "-C", "INPUT", "-s", ip, "-j", "DROP"])
    if exists_result.returncode != 0:
        write_alert(f"[ACTION] IP_NOT_BLOCKED ip={ip} via={binary}")
        return True

    delete_result = _run_cmd([binary, "-D", "INPUT", "-s", ip, "-j", "DROP"])
    if delete_result.returncode != 0:
        write_alert(
            f"[ERROR] Failed to unblock ip={ip} via {binary}: "
            f"{_format_command_error(delete_result)}"
        )
        return False

    write_alert(f"[ACTION] IP_UNBLOCKED ip={ip} via={binary}")
    return True


def load_blocked_ips_state():
    """Load persisted blocked IP metadata from JSON file."""
    if not os.path.exists(BLOCKED_IPS_FILE):
        return {}

    try:
        with open(BLOCKED_IPS_FILE, "r") as f:
            data = json.load(f)

        blocked_ips = data.get("blocked_ips", {})
        if isinstance(blocked_ips, dict):
            return blocked_ips
        return {}
    except (IOError, OSError, json.JSONDecodeError) as e:
        write_alert(f"[ERROR] Failed to load blocked IP state: {e}")
        return {}


def save_blocked_ips_state(blocked_ips):
    """Persist blocked IP metadata to JSON file."""
    payload = {
        "updated_at": datetime.utcnow().isoformat() + "Z",
        "ban_duration_seconds": BAN_DURATION_SECONDS,
        "blocked_ips": blocked_ips,
    }

    try:
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump(payload, f, indent=4)
    except (IOError, OSError) as e:
        write_alert(f"[ERROR] Failed to save blocked IP state: {e}")


def _safe_expires_at(entry):
    """Return a safe float expiry value from a persisted state entry."""
    try:
        return float((entry or {}).get("expires_at", 0))
    except (TypeError, ValueError):
        return 0.0


def block_ip(ip, blocked_ips_state=None):
    """
    Block an IP using available firewall backend.
    Safety checks:
      - Reject invalid IP values
      - Never block loopback/localhost addresses
    Returns True if blocked or already blocked, else False.
    """
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        write_alert(f"[ERROR] BLOCK_IP_INVALID ip={ip}")
        return False

    if parsed_ip.is_loopback:
        write_alert(f"[INFO] BLOCK_IP_SKIPPED_LOOPBACK ip={parsed_ip.compressed}")
        return False

    backend = _detect_firewall_backend()
    if not backend:
        write_alert("[ERROR] No supported firewall backend found (nft/iptables/ip6tables).")
        return False

    if backend == "nft":
        ok = _nft_add_block(parsed_ip)
    else:
        ok = _iptables_add_block(parsed_ip)

    if ok and blocked_ips_state is not None:
        now_ts = time.time()
        blocked_ips_state[parsed_ip.compressed] = {
            "blocked_at": now_ts,
            "expires_at": now_ts + BAN_DURATION_SECONDS,
            "backend": backend,
        }
        save_blocked_ips_state(blocked_ips_state)

    return ok


def unblock_ip(ip, blocked_ips_state=None):
    """Remove an IP block rule from the selected firewall backend."""
    try:
        parsed_ip = ipaddress.ip_address(ip)
    except ValueError:
        write_alert(f"[ERROR] UNBLOCK_IP_INVALID ip={ip}")
        return False

    backend = _detect_firewall_backend()
    if not backend:
        write_alert(
            "[ERROR] No supported firewall backend found (nft/iptables/ip6tables)."
        )
        return False

    if backend == "nft":
        ok = _nft_remove_block(parsed_ip)
    else:
        ok = _iptables_remove_block(parsed_ip)

    if ok and blocked_ips_state is not None:
        blocked_ips_state.pop(parsed_ip.compressed, None)
        save_blocked_ips_state(blocked_ips_state)

    return ok


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
    print(
        f"[INFO] Detection rule: >= {FAIL_THRESHOLD} failed attempts from "
        f"same IP within {WINDOW_SECONDS}s"
    )

    # Per-IP failed attempt timestamps (epoch seconds)
    failed_attempts_by_ip = defaultdict(deque)
    # Track IPs already alerted for brute-force in current failure streak
    bruteforce_alerted_ips = set()
    # Persisted blocked IP state (survives process restarts)
    blocked_ips = load_blocked_ips_state()

    # Re-apply active blocks after restart and clear expired bans.
    now_ts = time.time()
    for persisted_ip in list(blocked_ips.keys()):
        entry = blocked_ips.get(persisted_ip, {})
        expires_at = _safe_expires_at(entry)

        if expires_at <= now_ts:
            unblock_ip(persisted_ip, blocked_ips)
        else:
            block_ip(persisted_ip)

    try:
        with open(AUTH_LOG, "r") as log_file:
            # Move to the end of the file to only read new entries
            log_file.seek(0, 2)

            while True:
                line = log_file.readline()
                if line:
                    now_ts = time.time()

                    # Auto-unblock expired bans.
                    for blocked_ip in list(blocked_ips.keys()):
                        entry = blocked_ips.get(blocked_ip, {})
                        expires_at = _safe_expires_at(entry)
                        if expires_at <= now_ts:
                            unblock_ip(blocked_ip, blocked_ips)

                    ip = extract_ip(line)

                    # Skip lines that do not carry an IP
                    if not ip:
                        continue

                    if is_failed_ssh_attempt(line):
                        failed_attempts_by_ip[ip].append(now_ts)
                        prune_old_attempts(failed_attempts_by_ip, ip, now_ts)
                        attempt_count = len(failed_attempts_by_ip[ip])

                        if attempt_count >= FAIL_THRESHOLD and ip not in bruteforce_alerted_ips:
                            alert_bruteforce(ip, attempt_count)
                            bruteforce_alerted_ips.add(ip)

                            if ip not in blocked_ips:
                                block_ip(ip, blocked_ips)

                    elif is_successful_ssh_login(line):
                        prune_old_attempts(failed_attempts_by_ip, ip, now_ts)
                        failure_count = len(failed_attempts_by_ip[ip])

                        if failure_count >= FAIL_THRESHOLD:
                            alert_success_after_failures(ip, failure_count)

                        # Reset this IP after a successful login to begin a new streak.
                        failed_attempts_by_ip[ip].clear()
                        bruteforce_alerted_ips.discard(ip)
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
