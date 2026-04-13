"""
log_analyzer.py - Parse auth/syslog files and detect suspicious activity.
Supports: Linux auth.log, SSH logs, Apache/Nginx access logs.
"""

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


# ── Regex patterns ────────────────────────────────────────────────────────────
PATTERNS = {
    "ssh_failed": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    "ssh_success": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*Accepted (?:password|publickey) for (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    "ssh_invalid_user": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)"
    ),
    "sudo_usage": re.compile(
        r"(?P<timestamp>\w+\s+\d+\s+[\d:]+).*sudo.*COMMAND=(?P<command>.+)"
    ),
    "apache_access": re.compile(
        r"(?P<ip>[\d.]+).*\[(?P<timestamp>[^\]]+)\].*\"(?P<method>\w+)\s+(?P<path>\S+).*\"\s+(?P<status>\d{3})"
    ),
}

BRUTE_FORCE_THRESHOLD = 5   # failed attempts before flagging
PORT_SCAN_THRESHOLD   = 15  # unique ports from same IP in access logs


@dataclass
class AnalysisResult:
    log_file: str
    total_lines: int = 0
    events: list[dict] = field(default_factory=list)
    alerts: list[dict] = field(default_factory=list)
    ip_stats: dict = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    user_stats: dict = field(default_factory=lambda: defaultdict(int))


def analyze_log(filepath: str) -> AnalysisResult:
    """
    Parse a log file and return structured findings + alerts.

    Args:
        filepath: Path to auth.log, syslog, or Apache/Nginx access log.

    Returns:
        AnalysisResult with events, alerts, and statistics.
    """
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {filepath}")

    result = AnalysisResult(log_file=str(path.resolve()))
    failed_attempts: dict[str, list] = defaultdict(list)

    with open(path, "r", errors="ignore") as fh:
        for line in fh:
            result.total_lines += 1
            _parse_line(line.strip(), result, failed_attempts)

    _detect_brute_force(result, failed_attempts)
    return result


def _parse_line(line: str, result: AnalysisResult, failed: dict) -> None:
    for event_type, pattern in PATTERNS.items():
        m = pattern.search(line)
        if not m:
            continue

        groups = m.groupdict()
        event = {"type": event_type, "raw": line, **groups}
        result.events.append(event)

        ip   = groups.get("ip", "")
        user = groups.get("user", "")

        if event_type == "ssh_failed":
            result.ip_stats[ip]["failed_logins"] += 1
            result.user_stats[user] += 1
            failed[ip].append(groups.get("timestamp", ""))

        elif event_type == "ssh_success":
            result.ip_stats[ip]["successful_logins"] += 1

        elif event_type == "ssh_invalid_user":
            result.ip_stats[ip]["invalid_users"] += 1

        elif event_type == "apache_access":
            status = groups.get("status", "")
            result.ip_stats[ip]["requests"] += 1
            if status == "404":
                result.ip_stats[ip]["404s"] += 1

        break  # stop after first match per line


def _detect_brute_force(result: AnalysisResult, failed: dict) -> None:
    for ip, timestamps in failed.items():
        count = len(timestamps)
        if count >= BRUTE_FORCE_THRESHOLD:
            result.alerts.append({
                "severity": "HIGH" if count >= 20 else "MEDIUM",
                "type":     "BRUTE_FORCE",
                "ip":       ip,
                "attempts": count,
                "first_seen": timestamps[0],
                "last_seen":  timestamps[-1],
                "description": f"Brute-force attack detected: {count} failed SSH login attempts from {ip}",
            })

    # Flag IPs with high 404 rates (potential dir traversal / scanning)
    for ip, stats in result.ip_stats.items():
        if stats.get("404s", 0) >= PORT_SCAN_THRESHOLD:
            result.alerts.append({
                "severity":    "MEDIUM",
                "type":        "DIRECTORY_SCAN",
                "ip":          ip,
                "404_count":   stats["404s"],
                "description": f"Possible directory scanning from {ip} ({stats['404s']} 404 responses)",
            })


def summary(result: AnalysisResult) -> dict:
    """Return a concise summary dictionary from an AnalysisResult."""
    return {
        "log_file":    result.log_file,
        "total_lines": result.total_lines,
        "total_events": len(result.events),
        "total_alerts": len(result.alerts),
        "alerts_by_severity": {
            "HIGH":   sum(1 for a in result.alerts if a["severity"] == "HIGH"),
            "MEDIUM": sum(1 for a in result.alerts if a["severity"] == "MEDIUM"),
            "LOW":    sum(1 for a in result.alerts if a["severity"] == "LOW"),
        },
        "top_offending_ips": sorted(
            result.ip_stats.items(),
            key=lambda x: x[1].get("failed_logins", 0),
            reverse=True,
        )[:10],
        "alerts": result.alerts,
    }
