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

Python dependencies (from `requirements.txt`):

- psutil
- watchdog
- Flask
- fpdf2

Feature note:

- full SSH and firewall blocking features are Linux features
- Windows users should use WSL2 (recommended) for full functionality

---

## 4. Windows Setup and Usage (First)

This section is for Windows users.

### 4.1 Recommended: Use WSL2 (full features)

Why: this project monitors `/var/log/auth.log` and uses Linux firewall commands. Those are Linux-native.

### Step 1: Open WSL terminal and install packages

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip rsyslog openssh-server
sudo systemctl enable rsyslog --now
sudo systemctl enable ssh --now
```

### Step 2: Clone project in WSL and enter project root

```bash
git clone https://github.com/MrSdas10/HIDS.git hids-project
cd hids-project/HIDS
```

### Step 3: Create venv and install Python dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 4: Run HIDS engine (manual core)

Terminal 1:

```bash
cd ~/hids-project/HIDS
source .venv/bin/activate
sudo .venv/bin/python src/main.py
```

### Step 5: Run dashboard

Terminal 2:

```bash
cd ~/hids-project/HIDS
source .venv/bin/activate
.venv/bin/python src/report_download_server.py
```

Open browser in Windows:

- http://127.0.0.1:5001/

### Step 6A: Manual testing (1 by 1)

Terminal 3:

```bash
cd ~/hids-project/HIDS
echo "manual tamper test" >> monitored/important.txt
```

Terminal 4:

```bash
sudo bash -c 'for i in {1..3}; do echo "Mar 24 12:00:0$i hids sshd[$((3000+i))]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2" >> /var/log/auth.log; done'
```

Expected in Terminal 1:

- file modified alert
- SSH brute-force alert
- optional IP blocked action log

### Step 6B: Button-based testing

On dashboard click:

1. Simulate SSH Brute Force
2. Simulate File Modification
3. Simulate Full Attack Chain

Expected:

- alerts table updates automatically
- risk cards update
- events are appended to `alerts.log`

### Step 7: Report generation

Option 1 (button): click Download PDF Report.

Option 2 (CLI):

```bash
cd ~/hids-project/HIDS
source .venv/bin/activate
.venv/bin/python src/report_generator.py --input alerts.log --output hids_report_windows.pdf
```

---

## 5. Linux Setup and Usage (Second)

This section is for native Linux users (Kali/Ubuntu/Debian/Fedora/CentOS).

### Step 1: Install system packages

Kali/Ubuntu/Debian:

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip rsyslog openssh-server
sudo systemctl enable rsyslog --now
sudo systemctl enable ssh --now
```

### Step 2: Clone and enter project root

```bash
git clone https://github.com/MrSdas10/HIDS.git hids-project
cd hids-project/HIDS
```

### Step 3: Create venv and install dependencies

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Step 4: Start monitor engine

Terminal 1:

```bash
cd ~/hids-project/HIDS
source .venv/bin/activate
sudo .venv/bin/python src/main.py
```

### Step 5: Start dashboard

Terminal 2:

```bash
cd ~/hids-project/HIDS
source .venv/bin/activate
.venv/bin/python src/report_download_server.py
```

Open browser:

- http://127.0.0.1:5001/

### Step 6A: Manual testing (1 by 1)

Terminal 3 (file change):

```bash
cd ~/hids-project/HIDS
echo "manual tamper test" >> monitored/important.txt
```

Terminal 4 (SSH brute-force lines):

```bash
sudo bash -c 'for i in {1..3}; do echo "Mar 24 12:00:0$i hids sshd[$((3000+i))]: Failed password for invalid user admin from 203.0.113.77 port 22 ssh2" >> /var/log/auth.log; done'
```

Expected in Terminal 1:

- file modified alert
- SSH brute-force alert
- optional IP blocked action log

### Step 6B: Button-based testing

On dashboard click:

1. Simulate SSH Brute Force
2. Simulate File Modification
3. Simulate Full Attack Chain

### Step 7: Report generation

Option 1 (button): click Download PDF Report.

Option 2 (CLI):

```bash
cd ~/hids-project/HIDS
source .venv/bin/activate
.venv/bin/python src/report_generator.py --input alerts.log --output hids_report_linux.pdf
```

---

## 6. Optional API Testing (No UI)

If you want to trigger simulation from terminal:

```bash
curl -X POST http://127.0.0.1:5001/api/simulate \
    -H "Content-Type: application/json" \
    -d '{"event_type":"full_attack_chain"}'
```

Supported `event_type` values:

- ssh_bruteforce
- file_modification
- full_attack_chain

---

## 7. Security Behavior and Safe Defaults

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

## 8. Quick End-to-End Flow

1. Start monitor engine in terminal 1 (`src/main.py` with sudo).
2. Start dashboard in terminal 2 (`src/report_download_server.py`).
3. Open dashboard and click **Simulate Full Attack Chain**.
4. Watch alerts appear in real time.
5. Click **Download PDF Report**.
6. Verify report content in `reports/` and downloaded file.

---

## 9. Common Troubleshooting

### Kali path error: `can't open file ... src/main.py`

If you see errors like:

- `.venv/bin/python: can't open file '/home/user/HIDS/src/main.py'`
- `source: no such file or directory: .venv/bin/activate`

it usually means you are in the wrong folder, or `.venv` was created in a different folder.

Run these commands exactly:

```bash
# 1) Go to outer repo folder
cd ~/HIDS

# 2) Find where main.py actually exists
find . -maxdepth 3 -type f -name main.py

# 3) Enter the real project root (example output: ./HIDS/src/main.py)
cd ~/HIDS/HIDS

# 4) Verify this folder has src and requirements.txt
pwd
ls

# 5) Create venv INSIDE this same folder
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt

# 6) Run monitors
sudo "$(pwd)/.venv/bin/python" src/main.py
```

In a second terminal:

```bash
cd ~/HIDS/HIDS
source .venv/bin/activate
"$(pwd)/.venv/bin/python" src/report_download_server.py
```

Open dashboard:

- `http://127.0.0.1:5001/`

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

## 10. Stop and Cleanup

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

## 11. Tech Stack

- Python (threading, subprocess, json, hashlib)
- psutil
- Flask
- fpdf2

---

## 12. Next Recommended Improvements

- add authentication for dashboard in remote mode
- add HTTPS reverse proxy (Nginx/Caddy)
- move settings to config file (YAML/JSON)
- add pytest test suite and CI checks
- add alert persistence in SQLite/PostgreSQL

