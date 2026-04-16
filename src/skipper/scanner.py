"""
scanner.py - TCP Port Scanner with Banner Grabbing
"""

import socket
import concurrent.futures
from datetime import datetime


COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB",
}


def grab_banner(ip: str, port: int, timeout: float = 2.0) -> str:
    """Attempt to grab a service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            banner = s.recv(1024).decode(errors="ignore").strip()
            return banner[:200] if banner else "No banner"
    except Exception:
        return "No banner"


def scan_port(ip: str, port: int, timeout: float = 1.0) -> dict:
    """Scan a single TCP port and return result dict."""
    result = {
        "port": port,
        "state": "closed",
        "service": COMMON_PORTS.get(port, "unknown"),
        "banner": "",
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            if s.connect_ex((ip, port)) == 0:
                result["state"] = "open"
                result["banner"] = grab_banner(ip, port)
    except socket.error:
        pass
    return result


def scan_target(ip: str, ports: list[int] = None, threads: int = 100) -> dict:
    """
    Scan a target IP for open ports using thread pool.

    Args:
        ip:      Target IP address or hostname.
        ports:   List of ports to scan. Defaults to common ports.
        threads: Max concurrent threads.

    Returns:
        dict with scan metadata and open port results.
    """
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    # Resolve hostname to IP
    try:
        resolved_ip = socket.gethostbyname(ip)
    except socket.gaierror as e:
        return {"error": f"Cannot resolve host '{ip}': {e}"}

    start_time = datetime.utcnow()
    open_ports = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(scan_port, resolved_ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result["state"] == "open":
                open_ports.append(result)

    open_ports.sort(key=lambda x: x["port"])
    duration = (datetime.utcnow() - start_time).total_seconds()

    return {
        "target": ip,
        "resolved_ip": resolved_ip,
        "scanned_ports": len(ports),
        "open_ports": open_ports,
        "scan_duration_sec": round(duration, 2),
        "timestamp": start_time.isoformat() + "Z",
    }
