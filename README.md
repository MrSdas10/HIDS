# Host Intrusion Detection System (HIDS)

A lightweight, modular Linux HIDS built with Python.

This project monitors a host for:

- file integrity changes
- SSH brute-force behavior
- suspicious root processes

It also includes:

- automatic IP blocking (iptables or nftables)
- a live Flask dashboard
- attack simulation buttons
- downloadable PDF incident reports

---

## 1. What This Project Detects

### File Integrity Monitor

- file modified
- file deleted
- new file appears in monitored folder

### SSH Log Monitor

- multiple failed SSH logins from same IP within 2 minutes
- successful login after multiple failures
- optional automatic temporary IP blocking

### Process Monitor

- root-owned process not matching trusted whitelist

---

## 2. Current Project Structure

```text
HIDS/
├── alerts.log                  # Alert output (auto-generated)
├── baseline.json               # File integrity baseline
├── blocked_ips.json            # Temporary ban state (auto-generated)
├── monitored/
│   └── important.txt
├── reports/                    # Generated PDF reports (auto-generated)
├── requirements.txt
└── src/
    ├── main.py                 # Starts all monitoring threads
    ├── file_monitor.py         # File integrity detection
    ├── log_monitor.py          # SSH detection + IP block/unblock
    ├── process_monitor.py      # Suspicious root process detection
    ├── utils.py                # Shared helpers + alert descriptions
    ├── simulation.py           # Fake attack event generator
    ├── report_generator.py     # PDF report generation
    └── report_download_server.py  # Flask dashboard + simulation + download
```

---

## 3. Requirements

- Linux host (Ubuntu/Kali/Debian/Fedora/CentOS)
- Python 3.8+
- sudo/root privileges for full functionality
- SSH logs available in `/var/log/auth.log`

Python dependencies (from `requirements.txt`):

- psutil
- watchdog
- Flask
- fpdf2

---

## 4. Installation (Step by Step)

### Step 1: Clone and open project

```bash
git clone https://github.com/MrSdas10/HIDS.git hids-project
cd hids-project/HIDS
```

### Step 2: Create and activate virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install dependencies

```bash
pip install -r requirements.txt
```

### Step 4: Enable auth logging and SSH service (Kali/Ubuntu style)

```bash
sudo apt update
sudo apt install -y rsyslog openssh-server
sudo systemctl enable rsyslog --now
sudo systemctl enable ssh --now
```

Why this step matters:

- the SSH monitor tails `/var/log/auth.log`
- if auth events never reach this file, brute-force detection will not trigger

---

## 5. Run HIDS Monitors

Run in terminal 1:

```bash
cd hids-project/HIDS
source .venv/bin/activate
sudo .venv/bin/python src/main.py
```

What happens on startup:

- baseline is created/refreshed
- three monitor threads start
- alerts are printed and appended to `alerts.log`

---

## 6. Run Flask Dashboard

Run in terminal 2:

```bash
cd hids-project/HIDS
source .venv/bin/activate
.venv/bin/python src/report_download_server.py
```

Open browser:

- `http://127.0.0.1:5001/`

Dashboard features:

- live alert table (auto-refresh)
- risk summary cards
- simulation buttons
- PDF download button

---

## 7. Simulate Attacks (Same Detection Pipeline)

The dashboard buttons write events into real monitored sources, so detections run through the same pipeline as real attacks.

### Option A: From Dashboard buttons

- Simulate SSH Brute Force
- Simulate File Modification
- Simulate Full Attack Chain

### Option B: From API (localhost only by default)

```bash
curl -X POST http://127.0.0.1:5001/api/simulate \
    -H "Content-Type: application/json" \
    -d '{"event_type":"full_attack_chain"}'
```

Supported `event_type` values:

- `ssh_bruteforce`
- `file_modification`
- `full_attack_chain`

---

## 8. Generate and Download PDF Report

### Option A: From dashboard

- Click **Download PDF Report**
- A timestamped report is generated and downloaded

### Option B: From CLI

```bash
cd hids-project/HIDS
source .venv/bin/activate
.venv/bin/python src/report_generator.py --input alerts.log --output hids_report.pdf
```

Report includes:

- total alerts and risk breakdown
- incident details (time, IP, type, risk)
- explanation by attack type
- actions taken (for example IP blocked/unblocked)

---

## 9. Security Behavior and Safe Defaults

- dashboard endpoints are localhost-only by default
- simulation endpoint is localhost-only
- report download endpoint is localhost-only
- loopback addresses are never blocked by `block_ip()`
- IP blocking supports nftables or iptables/ip6tables
- temporary bans auto-expire and unblocking is automatic

If you intentionally need remote access:

```bash
.venv/bin/python src/report_download_server.py --host 0.0.0.0 --allow-remote
```

Important: only do this behind proper firewall/authentication.

---

## 10. Example End-to-End Workflow

1. Start monitor engine in terminal 1 (`src/main.py` with sudo).
2. Start dashboard in terminal 2 (`src/report_download_server.py`).
3. Open dashboard and click **Simulate Full Attack Chain**.
4. Watch alerts appear in real time.
5. Click **Download PDF Report**.
6. Verify report content in `reports/` and downloaded file.

---

## 11. Common Troubleshooting

### No SSH alerts appear

- ensure `rsyslog` is running
- ensure SSH service is active
- verify `/var/log/auth.log` receives new entries

### Permission errors reading auth.log or firewall operations

- run monitor process with `sudo`

### Dashboard loads but no data

- confirm `alerts.log` exists and has entries
- keep `src/main.py` running while testing

### PDF import error (`fpdf` not found)

- reinstall dependencies:

```bash
pip install -r requirements.txt
```

---

## 12. Stop and Cleanup

### Stop services

- press `Ctrl+C` in monitor and dashboard terminals

### Optional cleanup

```bash
> alerts.log
rm -f blocked_ips.json
rm -f reports/*.pdf
```

### Optional: disable test services on Kali after testing

```bash
sudo systemctl stop ssh rsyslog
sudo systemctl disable ssh rsyslog
```

---

## 13. Tech Stack

- Python (threading, subprocess, json, hashlib)
- psutil
- Flask
- fpdf2

---

## 14. Next Recommended Improvements

- add authentication for dashboard in remote mode
- add HTTPS reverse proxy (Nginx/Caddy)
- move settings to config file (YAML/JSON)
- add pytest test suite and CI checks
- add alert persistence in SQLite/PostgreSQL

