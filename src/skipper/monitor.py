"""
skipper.monitor
Live SIEM-like log monitoring for skipper.
"""
import time
import os
import re
from datetime import datetime

class LiveMonitor:
    def __init__(self, log_path, verbose=False, read_existing=True):
        self.log_path = log_path
        self.verbose = verbose
        self.read_existing = read_existing
        # Attack patterns
        self.patterns = {
            'SSH Brute Force': re.compile(r'Failed password', re.I),
            'SQL Injection': re.compile(r'(\'|%27|--).*(?:OR|AND|UNION|SELECT).*', re.I),
            'Path Traversal': re.compile(r'\.\./|\.\.\\|etc/passwd|boot\.ini', re.I),
            'Web Shell': re.compile(r'eval\(|system\(|exec\(|passthru\(', re.I),
            'Directory Scan': re.compile(r'GET /(admin|wp-admin|phpmyadmin|\.git|\.env)', re.I)
        }

    def analyze_line(self, line):
        """Check a single line for threats and print alerts."""
        #print(f"[DEBUG] Read: {line[:80]}")
        for threat, pattern in self.patterns.items():
            if pattern.search(line):
                ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', line)
                src_ip = ip_match.group(0) if ip_match else "unknown"
                timestamp = datetime.now().strftime("%H:%M:%S")
                alert = f"\033[91m[{timestamp}] ALERT: {threat} | IP: {src_ip}\n    Log: {line[:100]}...\033[0m"
                print(alert)
                return True
        if self.verbose:
            print(f"[{datetime.now().strftime('%H:%M:%S')}] {line[:80]}")
        return False

    def start(self):
        if not os.path.exists(self.log_path):
            print(f"[!] Error: Log file '{self.log_path}' not found.")
            return

        print(f"[*] skipper Live Monitor started on: {self.log_path}")
        print("[*] Press CTRL+C to stop.\n")

        try:
            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                if self.read_existing:
                    # Read all existing lines first
                    for line in f:
                        line = line.rstrip('\n')
                        if line:
                            self.analyze_line(line)
                    print("[*] Existing lines processed. Now tailing new entries...\n")

                # Now tail for new lines
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.5)
                        continue
                    self.analyze_line(line.rstrip('\n'))
        except KeyboardInterrupt:
            print("\n[!] Monitoring stopped.")
        except Exception as e:
            print(f"[!] Unexpected error: {e}")
