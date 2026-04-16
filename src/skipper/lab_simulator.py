"""
Lab Attack Simulator - Generates fake attack logs for training.
Run directly: python skipper/lab_simulator.py live_lab.log
"""
import random
import time
import sys
from datetime import datetime

IPS = ["192.168.1.105", "10.0.0.42", "172.16.0.99", "185.143.223.1"]

ATTACKS = [
    'Failed password for invalid user admin from {ip} port 45678 ssh2',
    'Failed password for root from {ip} port 22 ssh2',
    'GET /products.php?id=1\' OR \'1\'=\'1 HTTP/1.1" 200 452',
    'GET /?page=../../../../etc/passwd HTTP/1.1" 200 1024',
    'POST /wp-login.php HTTP/1.1" 200 3456',
    'GET /admin/config.php.bak HTTP/1.1" 403 234',
    'GET /.env HTTP/1.1" 404 196',
]

NORMAL = [
    'GET /index.html HTTP/1.1" 200 512',
    'GET /style.css HTTP/1.1" 200 1024',
    'GET /logo.png HTTP/1.1" 200 2048',
    'POST /search HTTP/1.1" 200 345',
]

def generate_line():
    ip = random.choice(IPS)
    now = datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
    if random.random() < 0.4:  # 40% chance of attack
        log = f'{ip} - - [{now}] "{random.choice(ATTACKS).format(ip=ip)}"'
    else:
        log = f'{ip} - - [{now}] "{random.choice(NORMAL)}"'
    return log

def main():
    outfile = sys.argv[1] if len(sys.argv) > 1 else "lab_access.log"
    print(f"[*] Generating fake SOC lab logs into {outfile}. Press CTRL+C to stop.")
    try:
        with open(outfile, 'a', encoding='utf-8') as f:
            while True:
                f.write(generate_line() + "\n")
                f.flush()
                time.sleep(random.uniform(1, 3))
    except KeyboardInterrupt:
        print(f"\n[!] Simulator stopped. Log saved to {outfile}")

if __name__ == "__main__":
    main()
