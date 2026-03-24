"""
simulation.py - HIDS attack simulation helpers

This module generates fake attack events by writing to the same sources
used by the real detectors:
- SSH brute force simulation writes to /var/log/auth.log
- File modification simulation edits files in monitored/

That means existing monitor modules can detect these events using
exactly the same pipeline as real events.
"""

import os
from datetime import datetime

from file_monitor import MONITORED_DIR
from log_monitor import AUTH_LOG, FAIL_THRESHOLD, ensure_auth_log


def _syslog_timestamp():
    """Build a syslog-like timestamp used in auth.log entries."""
    now = datetime.now()
    return f"{now.strftime('%b')} {now.day:2d} {now.strftime('%H:%M:%S')}"


def _append_auth_log_line(line):
    """Safely append one line to auth.log."""
    with open(AUTH_LOG, "a") as log_file:
        log_file.write(line.rstrip("\n") + "\n")


def simulate_ssh_bruteforce(ip="203.0.113.77", username="admin", attempts=None):
    """
    Simulate SSH brute-force failed logins from a single IP.

    Returns a dict with operation status and metadata.
    """
    if attempts is None:
        attempts = FAIL_THRESHOLD

    if attempts < 1:
        return {
            "ok": False,
            "event_type": "ssh_bruteforce",
            "message": "attempts must be >= 1",
        }

    if not ensure_auth_log():
        return {
            "ok": False,
            "event_type": "ssh_bruteforce",
            "message": f"Could not access auth log: {AUTH_LOG}",
        }

    try:
        for i in range(attempts):
            pid = 4000 + i
            line = (
                f"{_syslog_timestamp()} hids-sim sshd[{pid}]: Failed password "
                f"for invalid user {username} from {ip} port 22 ssh2"
            )
            _append_auth_log_line(line)

        return {
            "ok": True,
            "event_type": "ssh_bruteforce",
            "message": (
                f"Simulated {attempts} failed SSH attempts from {ip} in {AUTH_LOG}"
            ),
        }
    except (IOError, OSError, PermissionError) as e:
        return {
            "ok": False,
            "event_type": "ssh_bruteforce",
            "message": f"Failed to write SSH simulation events: {e}",
        }


def simulate_ssh_success_after_failures(ip="203.0.113.77", username="admin"):
    """
    Simulate a successful SSH login from the same attacking IP.

    Returns a dict with operation status and metadata.
    """
    if not ensure_auth_log():
        return {
            "ok": False,
            "event_type": "ssh_success_after_failures",
            "message": f"Could not access auth log: {AUTH_LOG}",
        }

    try:
        line = (
            f"{_syslog_timestamp()} hids-sim sshd[4999]: Accepted password "
            f"for {username} from {ip} port 22 ssh2"
        )
        _append_auth_log_line(line)
        return {
            "ok": True,
            "event_type": "ssh_success_after_failures",
            "message": (
                f"Simulated successful SSH login from {ip} in {AUTH_LOG}"
            ),
        }
    except (IOError, OSError, PermissionError) as e:
        return {
            "ok": False,
            "event_type": "ssh_success_after_failures",
            "message": f"Failed to write SSH success simulation event: {e}",
        }


def simulate_file_modification(filename="important.txt"):
    """
    Simulate file tampering by appending data to a monitored file.

    Returns a dict with operation status and metadata.
    """
    try:
        os.makedirs(MONITORED_DIR, exist_ok=True)
        target_path = os.path.join(MONITORED_DIR, filename)

        with open(target_path, "a") as f:
            f.write(
                f"\n[SIMULATION] suspicious file change at "
                f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            )

        return {
            "ok": True,
            "event_type": "file_modification",
            "message": f"Simulated file modification in {target_path}",
        }
    except (IOError, OSError, PermissionError) as e:
        return {
            "ok": False,
            "event_type": "file_modification",
            "message": f"Failed to simulate file modification: {e}",
        }


def simulate_full_attack_chain(ip="203.0.113.77", username="admin"):
    """
    Simulate one complete attack chain:
      1) SSH brute-force failures
      2) Successful login after failures
      3) File tampering in monitored/
    """
    brute_result = simulate_ssh_bruteforce(ip=ip, username=username)
    if not brute_result.get("ok"):
        return {
            "ok": False,
            "event_type": "full_attack_chain",
            "message": f"Full chain failed at brute-force step: {brute_result.get('message')}",
        }

    success_result = simulate_ssh_success_after_failures(ip=ip, username=username)
    if not success_result.get("ok"):
        return {
            "ok": False,
            "event_type": "full_attack_chain",
            "message": f"Full chain failed at success step: {success_result.get('message')}",
        }

    file_result = simulate_file_modification()
    if not file_result.get("ok"):
        return {
            "ok": False,
            "event_type": "full_attack_chain",
            "message": f"Full chain failed at file step: {file_result.get('message')}",
        }

    return {
        "ok": True,
        "event_type": "full_attack_chain",
        "message": (
            "Simulated full attack chain: brute force, successful login, "
            "and file modification."
        ),
    }


def simulate_event(event_type):
    """Dispatch simulation by event type name."""
    normalized = (event_type or "").strip().lower()

    if normalized in {"ssh", "ssh_bruteforce", "ssh_brute_force"}:
        return simulate_ssh_bruteforce()
    if normalized in {"file", "file_modification", "file_change"}:
        return simulate_file_modification()
    if normalized in {"full", "full_attack_chain", "attack_chain"}:
        return simulate_full_attack_chain()

    return {
        "ok": False,
        "event_type": normalized or "unknown",
        "message": (
            "Unsupported simulation type. Use ssh_bruteforce, "
            "file_modification, or full_attack_chain."
        ),
    }
