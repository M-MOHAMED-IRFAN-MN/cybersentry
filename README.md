# 🛡️ CyberSentry

**Python SOC Automation & Recon Toolkit**

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776ab?logo=python&logoColor=white)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)](#testing)
[![Made for](https://img.shields.io/badge/Made%20for-SOC%20%7C%20Pentest-blue)](#)

> A command-line toolkit for **Security Operations Center (SOC)** analysts and **penetration testers** — combining port scanning, IP threat intelligence, and log-based anomaly detection in one cohesive tool.

⭐ Star this repo if you find it useful!

---

## ✨ Features

| Feature | Description |
|---|---|
| 🔍 **Port Scanner** | Multi-threaded TCP scan with automatic banner grabbing |
| 🌐 **IP Threat Intel** | AbuseIPDB integration — abuse score, country, ISP, TOR detection |
| 📋 **Log Analyzer** | Parse `auth.log` / Apache logs; detect brute-force, directory scans |
| 📊 **Report Generator** | Professional dark-theme HTML reports for all modules |

---

## 📸 Demo

```bash
# Scan a target for open ports
$ cybersentry scan 192.168.1.1

  ____      _               ____            _
 / ___|   _| |__   ___ _ __/ ___|  ___ _ __ | |_ _ __ _   _
...

[*] Scanning 192.168.1.1 ...

[+] Open ports on 192.168.1.1:
       22/tcp  SSH              SSH-2.0-OpenSSH_8.9
       80/tcp  HTTP             HTTP/1.1 200 OK Server: nginx/1.24
      443/tcp  HTTPS            No banner
     3306/tcp  MySQL            No banner

[*] Scan complete: 4 open / 17 scanned in 1.83s
```

```bash
# Analyze a log file for suspicious activity
$ cybersentry analyze samples/sample_auth.log

[+] Lines parsed   : 20
[+] Events detected: 18
[+] Alerts         : 2 (HIGH=1, MEDIUM=1)

[!] Alerts:
    [HIGH  ] BRUTE_FORCE          185.220.101.42   Brute-force attack detected: 10 failed SSH...
    [MEDIUM] BRUTE_FORCE          45.142.212.10    Brute-force attack detected: 6 failed SSH...
```

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/M-MOHAMED-IRFAN-MN/cybersentry.git
cd cybersentry

# (Optional) create a virtual environment
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate

# Install in editable mode
" pip install -e . "
```

> **Requirements:** Python 3.10+ · No third-party runtime dependencies (uses stdlib only)

---

## 🔧 Usage

### Port Scanner

```bash
# Scan common ports on a host
cybersentry scan <target>

# Scan specific ports
cybersentry scan 10.10.10.10 -p 22,80,443,8080,3306

# Save results as an HTML report
cybersentry scan 10.10.10.10 -r report.html

# Also output raw JSON
cybersentry scan 10.10.10.10 --json
```

### IP Threat Intelligence

```bash
# Set your AbuseIPDB key (free at abuseipdb.com)
export ABUSEIPDB_API_KEY="your_key_here"

# Check single IP
cybersentry intel 185.220.101.42

# Check multiple IPs (comma-separated)
cybersentry intel 185.220.101.42,45.142.212.10,8.8.8.8

# With inline API key + HTML report
cybersentry intel 185.220.101.42 -k YOUR_KEY -r threat_report.html
```

### Log Analyzer

```bash
# Analyze Linux auth.log
cybersentry analyze /var/log/auth.log

# Analyze sample log (included in repo)
cybersentry analyze samples/sample_auth.log

# Save findings to HTML report
cybersentry analyze /var/log/auth.log -r log_report.html
```

---

## 📁 Project Structure

```
cybersentry/
├── cybersentry/
│   ├── __init__.py        # Package metadata
│   ├── scanner.py         # TCP port scanner + banner grabbing
│   ├── threat_intel.py    # AbuseIPDB IP reputation lookup
│   ├── log_analyzer.py    # Auth/access log parser & alert engine
│   ├── reporter.py        # HTML report generator
│   └── cli.py             # Argparse CLI entry point
├── tests/
│   └── test_cybersentry.py  # Pytest unit tests (22 assertions)
├── samples/
│   └── sample_auth.log    # Demo log with brute-force events
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## 🧪 Testing

```bash
# Install dev dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=cybersentry --cov-report=term-missing
```

---

## 🛠️ Architecture

```
CLI (cli.py)
    │
    ├── scanner.py         ThreadPoolExecutor → socket.connect_ex → banner_grab
    ├── threat_intel.py    urllib.request → AbuseIPDB REST API → @lru_cache
    ├── log_analyzer.py    Regex engine → defaultdict counters → alert rules
    └── reporter.py        String templates → dark-theme HTML output
```

All modules are **independent** — use them as a library in your own scripts:

```python
from cybersentry.scanner import scan_target
from cybersentry.log_analyzer import analyze_log, summary

results = scan_target("192.168.1.1", ports=[22, 80, 443])
print(results["open_ports"])
```

---

## ⚠️ Legal & Ethical Use

> **Only scan systems you own or have explicit written permission to test.**
> Unauthorized port scanning may be illegal in your jurisdiction.
> This tool is intended for educational, CTF, and authorized professional use only.

---

## 📜 License

MIT © 2025 MOHAMED IRFAN

---

## 🙏 References

- [AbuseIPDB API Docs](https://docs.abuseipdb.com/)
- [MITRE ATT&CK — Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
