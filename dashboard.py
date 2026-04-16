"""
Skipper SOC Dashboard - Captain's SIEM Web Interface
Run: python dashboard.py
Open: http://localhost:5000
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import sqlite3
import json
import os
import re
from datetime import datetime
from urllib.parse import urlparse, parse_qs

DB_FILE = "skipper_alerts.db"
LOG_FILE = "live_lab.log"

# ── Database Setup ──────────────────────────────────────────────
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        alert_type TEXT,
        ip TEXT,
        severity TEXT,
        description TEXT,
        status TEXT DEFAULT 'open',
        rule_name TEXT,
        attack_type TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS cases (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id INTEGER,
        timestamp TEXT,
        title TEXT,
        status TEXT DEFAULT 'open',
        analyst TEXT DEFAULT 'Mohamed Irfan',
        notes TEXT
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        source_ip TEXT,
        dest_ip TEXT,
        method TEXT,
        path TEXT,
        status_code TEXT,
        raw TEXT
    )""")
    conn.commit()

    # Seed sample alerts if empty
    c.execute("SELECT COUNT(*) FROM alerts")
    if c.fetchone()[0] == 0:
        sample_alerts = [
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "BRUTE_FORCE", "172.16.0.99", "Critical",
             "SSH brute force detected - 6 failed attempts in 30s", "open",
             "SKP001 - SSH Brute Force Attack Detected", "Network Attack"),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "SQL_INJECTION", "192.168.1.105", "High",
             "SQL Injection attempt on /products.php - OR 1=1 payload", "open",
             "SKP002 - SQL Injection Detected", "Web Attack"),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "DIR_TRAVERSAL", "10.0.0.42", "High",
             "Directory traversal attempt - /../../../etc/passwd", "open",
             "SKP003 - Directory Traversal Detected", "Web Attack"),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "ENV_SCAN", "10.0.0.42", "Medium",
             "Environment file scan detected - GET /.env", "open",
             "SKP004 - Sensitive File Access Attempt", "Recon"),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "WP_ATTACK", "172.16.0.99", "Critical",
             "WordPress login brute force - POST /wp-login.php", "closed",
             "SKP005 - WordPress Brute Force Detected", "Web Attack"),
            (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "CONFIG_ACCESS", "192.168.1.105", "Medium",
             "Config file access - /admin/config.php.bak", "closed",
             "SKP006 - Backup Config File Access", "Recon"),
        ]
        c.executemany("""INSERT INTO alerts
            (timestamp, alert_type, ip, severity, description, status, rule_name, attack_type)
            VALUES (?,?,?,?,?,?,?,?)""", sample_alerts)

    # Seed sample logs if empty
    c.execute("SELECT COUNT(*) FROM logs")
    if c.fetchone()[0] == 0:
        sample_logs = [
            ("2026/04/13 22:08:35", "10.0.0.42", "server", "GET", "/.env", "404", '10.0.0.42 - - "GET /.env HTTP/1.1" 404'),
            ("2026/04/13 22:08:37", "172.16.0.99", "server", "POST", "/wp-login.php", "200", '172.16.0.99 - - "POST /wp-login.php HTTP/1.1" 200'),
            ("2026/04/13 22:08:39", "185.143.223.1", "server", "POST", "/search", "200", '185.143.223.1 - - "POST /search HTTP/1.1" 200'),
            ("2026/04/13 22:08:41", "192.168.1.105", "server", "GET", "/logo.png", "200", '192.168.1.105 - - "GET /logo.png HTTP/1.1" 200'),
            ("2026/04/13 22:08:43", "185.143.223.1", "server", "GET", "/products.php?id=1 OR 1=1", "200", '185.143.223.1 - - "GET /products.php?id=1 OR 1=1 HTTP/1.1" 200'),
            ("2026/04/13 22:08:50", "172.16.0.99", "server", "GET", "/../../../etc/passwd", "200", '172.16.0.99 - - "GET /../../../etc/passwd HTTP/1.1" 200'),
        ]
        c.executemany("""INSERT INTO logs (timestamp, source_ip, dest_ip, method, path, status_code, raw)
            VALUES (?,?,?,?,?,?,?)""", sample_logs)

    conn.commit()
    conn.close()

# Parse live_lab.log for fresh alerts
def parse_live_log():
    events = []
    if not os.path.exists(LOG_FILE):
        return events
    try:
        with open(LOG_FILE, "r", encoding="utf-8", errors="ignore") as f:
            for line in f.readlines()[-50:]:
                line = line.strip()
                if not line:
                    continue
                events.append({"raw": line, "time": datetime.now().strftime("%H:%M:%S")})
    except:
        pass
    return events

def get_alerts(status=None):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if status:
        c.execute("SELECT * FROM alerts WHERE status=? ORDER BY id DESC", (status,))
    else:
        c.execute("SELECT * FROM alerts ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_logs(search=""):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    if search:
        c.execute("SELECT * FROM logs WHERE raw LIKE ? ORDER BY id DESC LIMIT 100", (f"%{search}%",))
    else:
        c.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 100")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def get_cases():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("SELECT * FROM cases ORDER BY id DESC")
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def close_alert(alert_id):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("UPDATE alerts SET status='closed' WHERE id=?", (alert_id,))
    conn.commit()
    conn.close()

def create_case(alert_id, title):
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("INSERT INTO cases (alert_id, timestamp, title, status) VALUES (?,?,?,?)",
              (alert_id, datetime.now().strftime("%Y-%m-%d %H:%M:%S"), title, "open"))
    conn.commit()
    conn.close()

# ── HTML Template ────────────────────────────────────────────────
def render_page(title, content, active="monitoring"):
    nav_items = [
        ("monitoring", "📡", "Monitoring"),
        ("logs", "🔍", "Log Management"),
        ("cases", "📁", "Case Management"),
        ("endpoint", "🖥️", "Endpoint Security"),
        ("threat", "🎯", "Threat Intel"),
    ]
    nav_html = ""
    for key, icon, label in nav_items:
        active_class = "active" if key == active else ""
        nav_html += f'<a href="/{key}" class="nav-item {active_class}">{icon} {label}</a>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Skipper SOC - {title}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&family=Rajdhani:wght@400;600;700&display=swap');
  *{{margin:0;padding:0;box-sizing:border-box}}
  :root{{
    --bg:#0d1117;
    --sidebar:#161b22;
    --card:#1c2333;
    --border:#30363d;
    --accent:#00d4ff;
    --accent2:#7c3aed;
    --red:#ff4757;
    --orange:#ffa502;
    --yellow:#ffdd57;
    --green:#2ed573;
    --text:#e6edf3;
    --muted:#8b949e;
  }}
  body{{background:var(--bg);color:var(--text);font-family:'Rajdhani',sans-serif;display:flex;min-height:100vh}}
  .sidebar{{width:220px;background:var(--sidebar);border-right:1px solid var(--border);padding:20px 0;position:fixed;height:100vh;z-index:100}}
  .logo{{padding:0 20px 24px;border-bottom:1px solid var(--border);margin-bottom:16px}}
  .logo h1{{font-size:22px;font-weight:700;color:var(--accent);letter-spacing:2px}}
  .logo span{{font-size:11px;color:var(--muted);font-family:'JetBrains Mono',monospace}}
  .nav-item{{display:flex;align-items:center;gap:10px;padding:12px 20px;color:var(--muted);text-decoration:none;font-size:15px;font-weight:600;transition:all 0.2s;border-left:3px solid transparent}}
  .nav-item:hover{{color:var(--text);background:rgba(0,212,255,0.05);border-left-color:var(--accent)}}
  .nav-item.active{{color:var(--accent);background:rgba(0,212,255,0.1);border-left-color:var(--accent)}}
  .main{{margin-left:220px;flex:1;padding:24px}}
  .topbar{{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px}}
  .topbar h2{{font-size:24px;font-weight:700;letter-spacing:1px}}
  .badge{{display:inline-block;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:700;font-family:'JetBrains Mono',monospace}}
  .badge-critical{{background:rgba(255,71,87,0.2);color:var(--red);border:1px solid var(--red)}}
  .badge-high{{background:rgba(255,165,2,0.2);color:var(--orange);border:1px solid var(--orange)}}
  .badge-medium{{background:rgba(255,221,87,0.2);color:var(--yellow);border:1px solid var(--yellow)}}
  .badge-low{{background:rgba(46,213,115,0.2);color:var(--green);border:1px solid var(--green)}}
  .badge-open{{background:rgba(0,212,255,0.2);color:var(--accent);border:1px solid var(--accent)}}
  .badge-closed{{background:rgba(139,148,158,0.2);color:var(--muted);border:1px solid var(--muted)}}
  .tabs{{display:flex;gap:0;margin-bottom:20px;border-bottom:1px solid var(--border)}}
  .tab{{padding:10px 24px;cursor:pointer;font-size:14px;font-weight:600;color:var(--muted);text-decoration:none;border-bottom:2px solid transparent;transition:all 0.2s}}
  .tab.active{{color:var(--accent);border-bottom-color:var(--accent)}}
  .tab:hover{{color:var(--text)}}
  .card{{background:var(--card);border:1px solid var(--border);border-radius:8px;overflow:hidden;margin-bottom:20px}}
  .table{{width:100%;border-collapse:collapse}}
  .table th{{padding:12px 16px;text-align:left;font-size:12px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:1px;border-bottom:1px solid var(--border);background:rgba(0,0,0,0.2)}}
  .table td{{padding:14px 16px;font-size:14px;border-bottom:1px solid rgba(48,54,61,0.5)}}
  .table tr:hover td{{background:rgba(0,212,255,0.03)}}
  .table tr:last-child td{{border-bottom:none}}
  .action-btn{{padding:6px 14px;border-radius:4px;border:none;cursor:pointer;font-size:12px;font-weight:700;font-family:'Rajdhani',sans-serif;transition:all 0.2s}}
  .btn-take{{background:rgba(0,212,255,0.15);color:var(--accent);border:1px solid var(--accent)}}
  .btn-take:hover{{background:var(--accent);color:var(--bg)}}
  .btn-close{{background:rgba(255,71,87,0.15);color:var(--red);border:1px solid var(--red)}}
  .btn-close:hover{{background:var(--red);color:white}}
  .stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}}
  .stat-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;text-align:center}}
  .stat-num{{font-size:36px;font-weight:700;font-family:'JetBrains Mono',monospace}}
  .stat-label{{font-size:13px;color:var(--muted);margin-top:4px;font-weight:600}}
  .search-bar{{display:flex;gap:12px;margin-bottom:20px}}
  .search-bar input{{flex:1;background:var(--card);border:1px solid var(--border);border-radius:6px;padding:10px 16px;color:var(--text);font-size:14px;font-family:'JetBrains Mono',monospace}}
  .search-bar input:focus{{outline:none;border-color:var(--accent)}}
  .search-bar button{{background:var(--accent);color:var(--bg);border:none;border-radius:6px;padding:10px 20px;font-weight:700;cursor:pointer;font-family:'Rajdhani',sans-serif;font-size:14px}}
  .rule-name{{font-family:'JetBrains Mono',monospace;font-size:12px;color:var(--accent)}}
  .empty{{text-align:center;padding:60px;color:var(--muted)}}
  .empty h3{{font-size:18px;margin-bottom:8px}}
  .live-dot{{display:inline-block;width:8px;height:8px;background:var(--green);border-radius:50%;margin-right:8px;animation:pulse 1.5s infinite}}
  @keyframes pulse{{0%,100%{{opacity:1}}50%{{opacity:0.3}}}}
  .log-row{{font-family:'JetBrains Mono',monospace;font-size:11px}}
  .intel-card{{display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px}}
  .intel-stat{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:20px;display:flex;align-items:center;gap:16px}}
  .intel-icon{{font-size:32px}}
  .intel-num{{font-size:28px;font-weight:700;font-family:'JetBrains Mono',monospace;color:var(--accent)}}
  .intel-label{{font-size:12px;color:var(--muted)}}
  .endpoint-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}}
  .endpoint-card{{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:16px}}
  .endpoint-name{{font-size:16px;font-weight:700;margin-bottom:4px}}
  .endpoint-ip{{font-size:12px;color:var(--muted);font-family:'JetBrains Mono',monospace}}
  .endpoint-status{{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}}
  .status-online{{background:var(--green)}}
  .status-offline{{background:var(--red)}}
</style>
</head>
<body>
<div class="sidebar">
  <div class="logo">
    <h1>⚓ SKIPPER</h1>
    <span>Captain's SOC Toolkit</span>
  </div>
  {nav_html}
</div>
<div class="main">
  {content}
</div>
</body>
</html>"""


# ── Page Builders ────────────────────────────────────────────────
def page_monitoring(tab="main"):
    open_alerts = get_alerts("open")
    closed_alerts = get_alerts("closed")

    def sev_badge(s):
        s = s.lower()
        return f'<span class="badge badge-{s}">{s.upper()}</span>'

    def build_table(alerts, show_action=True):
        if not alerts:
            return '<div class="empty"><h3>No alerts found</h3><p>All clear — no threats detected</p></div>'
        rows = ""
        for a in alerts:
            action = ""
            if show_action:
                action = f'''
                  <form method="POST" action="/close_alert" style="display:inline">
                    <input type="hidden" name="id" value="{a['id']}">
                    <button class="action-btn btn-close" type="submit">Close</button>
                  </form>
                  <form method="POST" action="/create_case" style="display:inline;margin-left:6px">
                    <input type="hidden" name="alert_id" value="{a['id']}">
                    <input type="hidden" name="title" value="{a['rule_name']}">
                    <button class="action-btn btn-take" type="submit">Take</button>
                  </form>'''
            rows += f"""<tr>
              <td>{sev_badge(a['severity'])}</td>
              <td>{a['timestamp']}</td>
              <td class="rule-name">{a['rule_name']}</td>
              <td>{a['id']}</td>
              <td>{a['attack_type']}</td>
              <td>{action}</td>
            </tr>"""
        return f"""<table class="table">
          <thead><tr>
            <th>Severity</th><th>Date</th><th>Rule Name</th>
            <th>Event ID</th><th>Type</th><th>Action</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>"""

    main_active = "active" if tab == "main" else ""
    inv_active = "active" if tab == "investigation" else ""
    closed_active = "active" if tab == "closed" else ""

    if tab == "main":
        table = build_table(open_alerts)
    elif tab == "closed":
        table = build_table(closed_alerts, show_action=False)
    else:
        cases = get_cases()
        if not cases:
            table = '<div class="empty"><h3>Investigation Channel Empty</h3><p>Take ownership of an alert to start investigating</p></div>'
        else:
            rows = "".join(f"<tr><td>{c['id']}</td><td>{c['title']}</td><td>{c['analyst']}</td><td>{c['timestamp']}</td><td><span class='badge badge-open'>{c['status']}</span></td></tr>" for c in cases)
            table = f"""<table class="table">
              <thead><tr><th>Case ID</th><th>Title</th><th>Analyst</th><th>Date</th><th>Status</th></tr></thead>
              <tbody>{rows}</tbody></table>"""

    total = len(get_alerts())
    critical = len([a for a in get_alerts() if a['severity'] == 'Critical'])

    content = f"""
    <div class="topbar">
      <h2><span class="live-dot"></span>Monitoring</h2>
      <span style="color:var(--muted);font-size:13px;font-family:'JetBrains Mono',monospace">{datetime.now().strftime("%b %d, %Y %H:%M")}</span>
    </div>
    <div class="stats">
      <div class="stat-card"><div class="stat-num" style="color:var(--red)">{critical}</div><div class="stat-label">Critical Alerts</div></div>
      <div class="stat-card"><div class="stat-num" style="color:var(--accent)">{len(open_alerts)}</div><div class="stat-label">Open Alerts</div></div>
      <div class="stat-card"><div class="stat-num" style="color:var(--green)">{len(closed_alerts)}</div><div class="stat-label">Closed Alerts</div></div>
      <div class="stat-card"><div class="stat-num" style="color:var(--yellow)">{total}</div><div class="stat-label">Total Events</div></div>
    </div>
    <div class="tabs">
      <a class="tab {main_active}" href="/monitoring?tab=main">MAIN CHANNEL</a>
      <a class="tab {inv_active}" href="/monitoring?tab=investigation">INVESTIGATION CHANNEL</a>
      <a class="tab {closed_active}" href="/monitoring?tab=closed">CLOSED ALERTS</a>
    </div>
    <div class="card">{table}</div>"""
    return render_page("Monitoring", content, "monitoring")


def page_logs(search=""):
    logs = get_logs(search)
    rows = ""
    for l in logs:
        rows += f"""<tr class="log-row">
          <td>{l['timestamp']}</td>
          <td style="color:var(--accent)">{l['source_ip']}</td>
          <td style="color:var(--muted)">{l['dest_ip']}</td>
          <td><span class="badge badge-open">{l['method']}</span></td>
          <td style="color:var(--yellow)">{l['path'][:60]}</td>
          <td>{l['status_code']}</td>
        </tr>"""
    if not rows:
        rows = '<tr><td colspan="6" style="text-align:center;padding:40px;color:var(--muted)">No logs found</td></tr>'

    content = f"""
    <div class="topbar"><h2>🔍 Log Management</h2></div>
    <form method="GET" action="/logs">
    <div class="search-bar">
      <input name="search" placeholder="Search logs... (IP, path, method)" value="{search}">
      <button type="submit">Search</button>
    </div>
    </form>
    <p style="color:var(--muted);font-size:13px;margin-bottom:16px">{len(logs)} events found</p>
    <div class="card">
      <table class="table">
        <thead><tr>
          <th>Timestamp</th><th>Source IP</th><th>Dest</th>
          <th>Method</th><th>Path</th><th>Status</th>
        </tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""
    return render_page("Log Management", content, "logs")


def page_cases():
    cases = get_cases()
    rows = ""
    for c in cases:
        status_class = "open" if c['status'] == 'open' else "closed"
        rows += f"""<tr>
          <td>{c['id']}</td>
          <td>{c['title']}</td>
          <td>{c['analyst']}</td>
          <td>{c['timestamp']}</td>
          <td><span class="badge badge-{status_class}">{c['status'].upper()}</span></td>
        </tr>"""

    empty = ""
    if not cases:
        empty = '<div class="empty"><h3>No Cases Yet</h3><p>Go to Monitoring → take ownership of an alert to create a case</p></div>'

    content = f"""
    <div class="topbar"><h2>📁 Case Management</h2></div>
    <div class="tabs">
      <a class="tab active" href="/cases">All</a>
      <a class="tab" href="/cases">Open</a>
      <a class="tab" href="/cases">Closed</a>
    </div>
    <div class="card">
      {"<table class='table'><thead><tr><th>Case ID</th><th>Title</th><th>Analyst</th><th>Date</th><th>Status</th></tr></thead><tbody>" + rows + "</tbody></table>" if cases else empty}
    </div>"""
    return render_page("Case Management", content, "cases")


def page_endpoint():
    endpoints = [
        ("WS-Prod-02", "172.16.20.69", "online", "Windows Server", "High"),
        ("Stewart", "172.16.17.183", "online", "Windows 11", "Medium"),
        ("SharePoint01", "172.16.20.17", "online", "Windows Server", "Critical"),
        ("ubuntu-dev", "172.16.20.56", "online", "Ubuntu 22.04", "Low"),
        ("Jayne", "172.16.17.198", "offline", "Windows 10", "None"),
        ("Tomcat-Server02", "172.16.20.51", "online", "Ubuntu 20.04", "High"),
    ]
    cards = ""
    for name, ip, status, os_name, risk in endpoints:
        status_class = "status-online" if status == "online" else "status-offline"
        risk_class = risk.lower() if risk != "None" else "low"
        cards += f"""<div class="endpoint-card">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
            <div class="endpoint-name">🖥️ {name}</div>
            <span class="badge badge-{risk_class}">{risk}</span>
          </div>
          <div class="endpoint-ip"><span class="endpoint-status {status_class}"></span>{ip}</div>
          <div style="color:var(--muted);font-size:12px;margin-top:6px">{os_name}</div>
        </div>"""

    content = f"""
    <div class="topbar"><h2>🖥️ Endpoint Security</h2></div>
    <div class="endpoint-grid">{cards}</div>"""
    return render_page("Endpoint Security", content, "endpoint")


def page_threat():
    threat_data = [
        ("Apr, 12, 2026, 03:55 AM", "URL", "http://115.61.118.193:33166/bin.sh", "malware_download"),
        ("Apr, 12, 2026, 03:54 AM", "URL", "https://port5-send.plus8moran.in.net/0Sfe317c-0...", "malware_download"),
        ("Apr, 12, 2026, 03:52 AM", "URL", "http://42.227.204.231:36096/bin.sh", "malware_download"),
        ("Apr, 12, 2026, 03:49 AM", "IP", "185.143.223.1", "c2_server"),
        ("Apr, 12, 2026, 03:44 AM", "IP", "172.16.0.99", "brute_force"),
        ("Apr, 12, 2026, 03:43 AM", "Hash", "83e0cfc95de1153d405e839e53d408f5", "malware"),
        ("Apr, 12, 2026, 03:40 AM", "Domain", "windows-update.site", "phishing"),
        ("Apr, 12, 2026, 03:35 AM", "URL", "http://42.239.252.16:47389/bin.sh", "malware_download"),
    ]
    rows = ""
    for date, dtype, data, tag in threat_data:
        tag_color = "var(--red)" if "malware" in tag else "var(--orange)" if "c2" in tag else "var(--yellow)"
        rows += f"""<tr>
          <td style="color:var(--muted);font-size:12px">{date}</td>
          <td><span class="badge badge-open">{dtype}</span></td>
          <td style="font-family:'JetBrains Mono',monospace;font-size:12px">{data}</td>
          <td><span style="background:rgba(255,71,87,0.15);color:{tag_color};padding:3px 8px;border-radius:4px;font-size:11px">{tag}</span></td>
        </tr>"""

    content = f"""
    <div class="topbar"><h2>🎯 Threat Intelligence Feed</h2></div>
    <div class="intel-card">
      <div class="intel-stat"><div class="intel-icon">🔗</div><div><div class="intel-num">300254</div><div class="intel-label">URLs</div></div></div>
      <div class="intel-stat"><div class="intel-icon">🌐</div><div><div class="intel-num">2690</div><div class="intel-label">IPs</div></div></div>
      <div class="intel-stat"><div class="intel-icon">📄</div><div><div class="intel-num">382</div><div class="intel-label">Hashes</div></div></div>
      <div class="intel-stat"><div class="intel-icon">🏠</div><div><div class="intel-num">549</div><div class="intel-label">Domains</div></div></div>
    </div>
    <div class="card">
      <table class="table">
        <thead><tr><th>Date</th><th>Type</th><th>Data</th><th>Tag</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>"""
    return render_page("Threat Intel", content, "threat")


# ── HTTP Server ──────────────────────────────────────────────────
class Handler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  # Suppress default logs

    def send_html(self, html, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        params = parse_qs(parsed.query)

        if path in ["/", "/monitoring"]:
            tab = params.get("tab", ["main"])[0]
            self.send_html(page_monitoring(tab))
        elif path == "/logs":
            search = params.get("search", [""])[0]
            self.send_html(page_logs(search))
        elif path == "/cases":
            self.send_html(page_cases())
        elif path == "/endpoint":
            self.send_html(page_endpoint())
        elif path == "/threat":
            self.send_html(page_threat())
        else:
            self.send_html("<h1>404</h1>", 404)

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode("utf-8")
        params = parse_qs(body)
        path = urlparse(self.path).path

        if path == "/close_alert":
            alert_id = params.get("id", ["0"])[0]
            close_alert(int(alert_id))
        elif path == "/create_case":
            alert_id = params.get("alert_id", ["0"])[0]
            title = params.get("title", ["Unknown Alert"])[0]
            create_case(int(alert_id), title)
            close_alert(int(alert_id))

        self.send_response(302)
        self.send_header("Location", "/monitoring")
        self.end_headers()


# ── Main ─────────────────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    port = 5000
    server = HTTPServer(("0.0.0.0", port), Handler)
    print("=" * 50)
    print("  ⚓ SKIPPER SOC DASHBOARD")
    print("=" * 50)
    print(f"  Open browser: http://localhost:{port}")
    print(f"  Press CTRL+C to stop")
    print("=" * 50)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Dashboard stopped.")
