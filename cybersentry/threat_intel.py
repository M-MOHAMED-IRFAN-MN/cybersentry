"""
threat_intel.py - IP Reputation Lookup via AbuseIPDB
Requires a free API key from https://www.abuseipdb.com/
"""

import urllib.request
import urllib.parse
import json
import os
from functools import lru_cache


ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
_API_KEY = os.environ.get("ABUSEIPDB_API_KEY", "")


def set_api_key(key: str) -> None:
    """Set AbuseIPDB API key at runtime."""
    global _API_KEY
    _API_KEY = key


@lru_cache(maxsize=256)
def check_ip(ip: str, max_age_days: int = 90) -> dict:
    """
    Query AbuseIPDB for threat intelligence on an IP address.

    Args:
        ip:           IPv4 or IPv6 address to check.
        max_age_days: Look back window in days (max 365).

    Returns:
        dict with abuse score, country, ISP, and usage type.
    """
    if not _API_KEY:
        return {
            "ip": ip,
            "error": "No API key set. Use --api-key or set ABUSEIPDB_API_KEY env var.",
        }

    params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": max_age_days})
    url = f"{ABUSEIPDB_URL}?{params}"

    req = urllib.request.Request(
        url,
        headers={
            "Key": _API_KEY,
            "Accept": "application/json",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read())["data"]
            return {
                "ip": data.get("ipAddress"),
                "abuse_score": data.get("abuseConfidenceScore", 0),
                "country": data.get("countryCode", "N/A"),
                "isp": data.get("isp", "N/A"),
                "usage_type": data.get("usageType", "N/A"),
                "total_reports": data.get("totalReports", 0),
                "is_tor": data.get("isTor", False),
                "is_whitelisted": data.get("isWhitelisted", False),
                "last_reported": data.get("lastReportedAt", "Never"),
                "risk_level": _risk_level(data.get("abuseConfidenceScore", 0)),
            }
    except urllib.error.HTTPError as e:
        return {"ip": ip, "error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"ip": ip, "error": str(e)}


def _risk_level(score: int) -> str:
    if score >= 75:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def bulk_check(ips: list[str]) -> list[dict]:
    """Check multiple IPs and return list of results."""
    return [check_ip(ip) for ip in ips]
