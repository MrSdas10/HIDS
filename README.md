# Python Host Intrusion Detection System (HIDS)

A lightweight, multi-threaded Linux-based Host Intrusion Detection System built with Python. Designed as a real-world cybersecurity portfolio project for SOC Analyst internships.

---

## Project Description

This HIDS monitors a Linux host for common indicators of compromise (IOCs):

- **File integrity violations** — detects unauthorized modification or deletion of critical files.
- **SSH brute-force login attempts** — monitors authentication logs for repeated failed password entries.
- **Suspicious root processes** — flags unknown processes running with root privileges.

All alerts are timestamped and logged to both the console and an alert log file for forensic review.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────┐
│                   main.py                       │
│          (Initializer & Thread Manager)         │
├────────────────┬───────────────┬────────────────┤
│  Thread 1      │  Thread 2     │  Thread 3      │
│  File Monitor  │  SSH Log Mon. │  Process Mon.  │
│  (5s interval) │  (continuous) │  (10s interval)│
├────────────────┴───────────────┴────────────────┤
│                   utils.py                      │
│     (Hashing, Baseline I/O, Alert Logging)      │
└─────────────────────────────────────────────────┘
         │                           │
    baseline.json               alerts.log
```

### Module Breakdown

| Module              | Responsibility                              |
|---------------------|---------------------------------------------|
| `main.py`           | Entry point, thread orchestration           |
| `file_monitor.py`   | SHA256 hashing, baseline comparison         |
| `log_monitor.py`    | Auto-detects and tails SSH log for failed logins |
| `process_monitor.py`| Scans for non-whitelisted root processes    |
| `utils.py`          | Hashing, baseline I/O, alert logging        |

---

## Features

- SHA256 file integrity baseline and continuous comparison
- Real-time SSH brute-force detection with **auto-detected log file** (`auth.log`, `syslog`, or `secure`)
- Root process auditing with **expanded configurable whitelist** (40+ known safe processes)
- Kernel thread filtering to reduce false positives
- Thread health monitoring — alerts if a monitor thread dies unexpectedly
- Timestamped alerts to console and `alerts.log`
- Multi-threaded architecture (one thread per monitor)
- Compatible with **Kali Linux**, Ubuntu, Debian, CentOS, and Fedora
- Clean, modular, well-commented code (~250 lines)

---

## Directory Structure

```
HIDS/
│
├── src/
│   ├── main.py              # Entry point & thread manager
│   ├── file_monitor.py      # File integrity monitoring
│   ├── log_monitor.py       # SSH log monitoring
│   ├── process_monitor.py   # Suspicious process detection
│   └── utils.py             # Shared utility functions
│
├── monitored/
│   └── important.txt        # Sample file to monitor
│
├── baseline.json            # File hash baseline (auto-generated)
├── alerts.log               # Alert output log
├── requirements.txt         # Python dependencies
└── README.md                # Project documentation
```

---

## Installation

### Prerequisites

- Linux (Ubuntu, Kali Linux, Debian, CentOS, or Fedora)
- Python 3.8+
- `pip` package manager
- **rsyslog** (required on Kali Linux for SSH log monitoring)

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/MrSdas10/HIDS.git
cd HIDS

# 2. (Optional) Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. (Kali Linux only) Enable rsyslog for SSH log monitoring
sudo apt install rsyslog
sudo systemctl enable rsyslog --now
```

---

## How to Run

```bash
# Run with sudo (required for reading auth.log and process info)
sudo python3 src/main.py
```

### Expected Startup Output

```
============================================================
   Python Host Intrusion Detection System (HIDS)
   Lightweight Linux Security Monitoring Tool
============================================================
   Modules:
     [1] File Integrity Monitor
     [2] SSH Brute-Force Log Monitor
     [3] Suspicious Process Monitor
============================================================

[*] Initializing file integrity baseline...
[INFO] Baseline saved to baseline.json
[INFO] Baseline created with 1 file(s).

[*] Starting monitoring threads...

    [+] FileMonitor thread started.
    [+] SSHLogMonitor thread started.
    [+] ProcessMonitor thread started.

[*] HIDS is now running. Press Ctrl+C to stop.
```

---

## Attack Simulation & Testing

### Test 1: File Tampering

Modify a monitored file to trigger a file integrity alert.

```bash
echo "malicious change" >> monitored/important.txt
```

**Expected Output:**
```
[2026-03-08 14:30:00] [ALERT] File MODIFIED detected: /path/to/monitored/important.txt
```

### Test 2: SSH Brute-Force Attack

**Option A:** Use `hydra` to simulate failed SSH login attempts.

```bash
hydra -l testuser -P /usr/share/wordlists/rockyou.txt ssh://127.0.0.1
```

**Option B (recommended for quick testing):** Manually append a fake failed login line.

```bash
echo "Mar  8 14:35:00 kali sshd[1234]: Failed password for testuser from 192.168.1.100 port 22 ssh2" | sudo tee -a /var/log/auth.log
```

> **Note:** The SSH monitor auto-detects the correct log file for your distro:
> - Ubuntu/Debian/Kali: `/var/log/auth.log`
> - Fallback: `/var/log/syslog`
> - CentOS/RHEL/Fedora: `/var/log/secure`
>
> On Kali Linux, if no log file is found, install rsyslog:
> ```bash
> sudo apt install rsyslog && sudo systemctl enable rsyslog --now
> ```

**Expected Output:**
```
[2026-03-08 14:35:00] [ALERT] Failed SSH login attempt detected: Mar  8 14:35:00 kali sshd[1234]: Failed password for testuser from 192.168.1.100 port 22 ssh2
```

### Test 3: Suspicious Root Process

Run a suspicious process as root.

```bash
sudo python3 -c "while True: pass"
```

**Expected Output:**
```
[2026-03-08 14:40:00] [WARNING] Suspicious root process detected: PID=9876 Name=python3 User=root
```

---

## Screenshots

> Add screenshots of your HIDS running and detecting attacks here.
>
> Suggested screenshots:
> 1. HIDS startup output
> 2. File modification alert
> 3. SSH brute-force alert
> 4. Suspicious process alert
> 5. Contents of `alerts.log`

---

## Future Improvements

- [ ] **Email/Slack alerting** — Send real-time notifications on detection
- [ ] **Web dashboard** — Flask/Django UI to visualize alerts
- [ ] **Database logging** — Store alerts in SQLite or PostgreSQL
- [ ] **Network monitoring** — Detect port scans and anomalous connections
- [ ] **YARA rule integration** — Scan files for malware signatures
- [ ] **Configuration file** — YAML/JSON config for whitelist, paths, intervals
- [ ] **Log rotation support** — Handle auth.log rotation gracefully
- [ ] **Systemd service** — Run HIDS as a background Linux service
- [ ] **Unit tests** — pytest-based test suite for all modules

---

## Tech Stack

| Technology | Purpose                        |
|------------|--------------------------------|
| Python 3   | Core language                  |
| psutil     | Process inspection             |
| hashlib    | SHA256 file hashing            |
| threading  | Concurrent module execution    |
| json       | Baseline storage               |
| os / time  | File system and timing ops     |

