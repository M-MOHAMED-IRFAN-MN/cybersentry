"""
cli.py - skipper Command Line Interface
"""

import argparse
import json
import sys

from skipper import scanner, threat_intel, log_analyzer, reporter, monitor
from skipper.monitor import LiveMonitor


BANNER = r"""
   _____ _    _                  
  / ____| |  (_)                 
 | (___ | | ___ _ __  _ __   ___ _ __ 
  \___ \| |/ / | '_ \| '_ \ / _ \ '__|
  ____) |   <| | |_) | |_) |  __/ |   
 |_____/|_|\_\_| .__/| .__/ \___|_|   
               | |   | |               
               |_|   |_|               

     ⚓  Captain's SOC Toolkit  ⚓
        .Free. Forever. Yours.
"""


def cmd_scan(args):
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            print("[!] Invalid port list. Use comma-separated integers, e.g. 22,80,443")
            sys.exit(1)

    print(f"[*] Scanning {args.target} ...")
    results = scanner.scan_target(args.target, ports=ports)

    if "error" in results:
        print(f"[!] Error: {results['error']}")
        sys.exit(1)

    print(f"\n[+] Open ports on {results['resolved_ip']} ({args.target}):")
    for p in results["open_ports"]:
        print(f"    {p['port']:>5}/tcp  {p['service']:<15}  {p['banner'][:80]}")

    print(
        f"\n[*] Scan complete: {len(results['open_ports'])} open / {results['scanned_ports']} scanned in {results['scan_duration_sec']}s"
    )

    if args.report:
        path = reporter.generate_report(scan_results=results, output_path=args.report)
        print(f"[+] HTML report saved → {path}")

    if args.json:
        print(json.dumps(results, indent=2))


def cmd_intel(args):
    if args.api_key:
        threat_intel.set_api_key(args.api_key)

    ips = [ip.strip() for ip in args.ips.split(",")]
    print(f"[*] Checking {len(ips)} IP(s) against AbuseIPDB ...")
    results = threat_intel.bulk_check(ips)

    for r in results:
        if "error" in r:
            print(f"[!] {r['ip']}: {r['error']}")
        else:
            risk = r["risk_level"]
            icon = "🔴" if risk == "HIGH" else "🟡" if risk == "MEDIUM" else "🟢"
            print(
                f"  {icon} {r['ip']:>15}  Score: {r['abuse_score']:>3}  [{risk}]  Country: {r['country']}  ISP: {r['isp']}"
            )

    if args.report:
        path = reporter.generate_report(threat_results=results, output_path=args.report)
        print(f"[+] HTML report saved → {path}")


def cmd_analyze(args):
    print(f"[*] Analyzing log file: {args.logfile}")
    try:
        result = log_analyzer.analyze_log(args.logfile)
    except FileNotFoundError as e:
        print(f"[!] {e}")
        sys.exit(1)

    s = log_analyzer.summary(result)
    print(f"\n[+] Lines parsed   : {s['total_lines']:,}")
    print(f"[+] Events detected: {s['total_events']}")
    print(
        f"[+] Alerts         : {s['total_alerts']} (HIGH={s['alerts_by_severity']['HIGH']}, MEDIUM={s['alerts_by_severity']['MEDIUM']})"
    )

    if s["alerts"]:
        print("\n[!] Alerts:")
        for a in s["alerts"]:
            print(
                f"    [{a['severity']:6}] {a['type']:<20} {a.get('ip','N/A'):>15}  {a['description']}"
            )

    if args.report:
        path = reporter.generate_report(log_summary=s, output_path=args.report)
        print(f"\n[+] HTML report saved → {path}")


def cmd_monitor(args):
    """Handle the 'monitor' subcommand - real-time SIEM mode."""
    print(f"[*] Starting real-time monitor on: {args.logfile}")
    try:
        mon = LiveMonitor(args.logfile, verbose=args.verbose)
        mon.start()
    except KeyboardInterrupt:
        print("\n[!] Monitor stopped by user.")
    except Exception as e:
        print(f"[!] Error: {e}")
        sys.exit(1)


def cmd_guide(args):
    """Print the Free SOC Lab tutorial."""
    guide_text = """
╔══════════════════════════════════════════════════════════════════╗
║                  🛡️  FREE SOC ANALYST LAB  🛡️                    ║
║                   Learn Detection Like a Pro                      ║
╚══════════════════════════════════════════════════════════════════╝

skipper now includes a real‑time SIEM‑like monitor and an attack
simulator so you can practice threat detection without paying a cent.

┌──────────────────────────────────────────────────────────────────┐
│ 1. START THE MONITOR (Terminal 1)                                │
├──────────────────────────────────────────────────────────────────┤
│   skipper monitor live_lab.log                               │
│                                                                    │
│   (This tails the log and shows alerts as they happen)            │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ 2. START THE ATTACK SIMULATOR (Terminal 2)                       │
├──────────────────────────────────────────────────────────────────┤
│   python skipper/lab_simulator.py live_lab.log               │
│                                                                    │
│   (This generates SSH brute‑force, SQLi, path traversal etc.)     │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ 3. WATCH ALERTS IN REAL TIME                                     │
├──────────────────────────────────────────────────────────────────┤
│   Switch back to Terminal 1. You will see red alerts like:        │
│                                                                    │
│   [14:23:05] ALERT: SSH Brute Force | IP: 192.168.1.105          │
│   [14:23:08] ALERT: SQL Injection | IP: 10.0.0.42                │
│                                                                    │
│   Press CTRL+C in each terminal to stop.                          │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ 📊 OTHER COMMANDS                                                 │
├──────────────────────────────────────────────────────────────────┤
│   skipper analyze <logfile>   – Historical threat hunting     │
│   skipper scan <target>       – Port scanning & banner grab   │
│   skipper intel <IP>          – IP reputation check           │
│   skipper guide               – Show this tutorial            │
└──────────────────────────────────────────────────────────────────┘

Want to contribute? Visit: https://github.com/M-MOHAMED-IRFAN-MN/skipper
"""
    print(guide_text)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="skipper",
        description="skipper — Python SOC Automation & Recon Toolkit",
    )
    sub = p.add_subparsers(dest="command", required=True)

    # scan
    scan_p = sub.add_parser("scan", help="TCP port scan with banner grabbing")
    scan_p.add_argument("target", help="IP address or hostname to scan")
    scan_p.add_argument(
        "-p", "--ports", help="Comma-separated ports (default: common ports)"
    )
    scan_p.add_argument(
        "-r", "--report", metavar="FILE", help="Save HTML report to FILE"
    )
    scan_p.add_argument("--json", action="store_true", help="Also print JSON output")
    scan_p.set_defaults(func=cmd_scan)

    # intel
    intel_p = sub.add_parser("intel", help="IP reputation lookup via AbuseIPDB")
    intel_p.add_argument("ips", help="Comma-separated IP addresses")
    intel_p.add_argument("-k", "--api-key", help="AbuseIPDB API key")
    intel_p.add_argument(
        "-r", "--report", metavar="FILE", help="Save HTML report to FILE"
    )
    intel_p.set_defaults(func=cmd_intel)

    # analyze
    log_p = sub.add_parser(
        "analyze", help="Parse log file and detect suspicious activity"
    )
    log_p.add_argument("logfile", help="Path to auth.log, syslog, or Apache access log")
    log_p.add_argument(
        "-r", "--report", metavar="FILE", help="Save HTML report to FILE"
    )
    log_p.set_defaults(func=cmd_analyze)

    # monitor
    monitor_p = sub.add_parser(
        "monitor", help="Real-time log monitoring (SIEM-like tail)"
    )
    monitor_p.add_argument(
        "logfile", help="Path to log file to monitor (e.g., /var/log/auth.log)"
    )
    monitor_p.add_argument(
        "-v", "--verbose", action="store_true", help="Show all lines, not just alerts"
    )
    monitor_p.set_defaults(func=cmd_monitor)

    # guide
    guide_p = sub.add_parser("guide", help="Show tutorial for the free SOC lab")
    guide_p.set_defaults(func=cmd_guide)

    return p


def main():
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
