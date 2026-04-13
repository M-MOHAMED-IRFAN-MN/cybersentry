"""
reporter.py - Generate professional HTML security reports from scan/analysis results.
"""

from datetime import datetime, timezone
from pathlib import Path


_SEVERITY_COLOR = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#27ae60"}
_STATE_COLOR    = {"open": "#27ae60", "closed": "#e74c3c"}


def generate_report(
    scan_results: dict = None,
    log_summary: dict  = None,
    threat_results: list[dict] = None,
    output_path: str = "cybersentry_report.html",
) -> str:
    """
    Build an HTML report combining any available data sources.

    Args:
        scan_results:   Output from scanner.scan_target()
        log_summary:    Output from log_analyzer.summary()
        threat_results: Output from threat_intel.bulk_check()
        output_path:    Where to write the HTML file.

    Returns:
        Absolute path of the created report.
    """
    now = datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = []

    if scan_results:
        sections.append(_port_scan_section(scan_results))

    if log_summary:
        sections.append(_log_analysis_section(log_summary))

    if threat_results:
        sections.append(_threat_intel_section(threat_results))

    html = _wrap_page(now, "\n".join(sections))
    out = Path(output_path)
    out.write_text(html, encoding="utf-8")
    return str(out.resolve())


# ── Section builders ──────────────────────────────────────────────────────────

def _port_scan_section(data: dict) -> str:
    if "error" in data:
        return f'<section><h2>Port Scan</h2><p class="error">{data["error"]}</p></section>'

    rows = ""
    for p in data.get("open_ports", []):
        rows += f"""
        <tr>
            <td>{p['port']}</td>
            <td><span class="badge open">OPEN</span></td>
            <td>{p['service']}</td>
            <td class="banner">{_esc(p['banner'])}</td>
        </tr>"""

    return f"""
    <section>
        <h2>🔍 Port Scan Results</h2>
        <div class="meta-grid">
            <div class="meta-item"><label>Target</label><span>{data['target']}</span></div>
            <div class="meta-item"><label>Resolved IP</label><span>{data['resolved_ip']}</span></div>
            <div class="meta-item"><label>Ports Scanned</label><span>{data['scanned_ports']}</span></div>
            <div class="meta-item"><label>Open Ports</label><span>{len(data['open_ports'])}</span></div>
            <div class="meta-item"><label>Duration</label><span>{data['scan_duration_sec']}s</span></div>
            <div class="meta-item"><label>Timestamp</label><span>{data['timestamp']}</span></div>
        </div>
        <table>
            <thead><tr><th>Port</th><th>State</th><th>Service</th><th>Banner</th></tr></thead>
            <tbody>{rows if rows else '<tr><td colspan="4">No open ports found.</td></tr>'}</tbody>
        </table>
    </section>"""


def _log_analysis_section(data: dict) -> str:
    alert_rows = ""
    for a in data.get("alerts", []):
        color = _SEVERITY_COLOR.get(a["severity"], "#999")
        alert_rows += f"""
        <tr>
            <td><span class="badge" style="background:{color}">{a['severity']}</span></td>
            <td>{a['type']}</td>
            <td>{a.get('ip', 'N/A')}</td>
            <td>{_esc(a['description'])}</td>
        </tr>"""

    sev = data.get("alerts_by_severity", {})
    return f"""
    <section>
        <h2>📋 Log Analysis</h2>
        <div class="meta-grid">
            <div class="meta-item"><label>Log File</label><span>{data['log_file']}</span></div>
            <div class="meta-item"><label>Lines Parsed</label><span>{data['total_lines']:,}</span></div>
            <div class="meta-item"><label>Events Found</label><span>{data['total_events']}</span></div>
            <div class="meta-item"><label>HIGH Alerts</label><span style="color:#e74c3c;font-weight:700">{sev.get('HIGH',0)}</span></div>
            <div class="meta-item"><label>MEDIUM Alerts</label><span style="color:#f39c12;font-weight:700">{sev.get('MEDIUM',0)}</span></div>
        </div>
        <table>
            <thead><tr><th>Severity</th><th>Type</th><th>Source IP</th><th>Description</th></tr></thead>
            <tbody>{alert_rows if alert_rows else '<tr><td colspan="4">No alerts detected.</td></tr>'}</tbody>
        </table>
    </section>"""


def _threat_intel_section(results: list[dict]) -> str:
    rows = ""
    for r in results:
        if "error" in r:
            rows += f'<tr><td>{r["ip"]}</td><td colspan="6" class="error">{r["error"]}</td></tr>'
            continue
        score = r.get("abuse_score", 0)
        color = _SEVERITY_COLOR.get(r.get("risk_level", "LOW"), "#27ae60")
        rows += f"""
        <tr>
            <td>{r['ip']}</td>
            <td><strong style="color:{color}">{score}</strong></td>
            <td><span class="badge" style="background:{color}">{r.get('risk_level','N/A')}</span></td>
            <td>{r.get('country','N/A')}</td>
            <td>{r.get('isp','N/A')}</td>
            <td>{r.get('total_reports',0)}</td>
            <td>{'⚠️ TOR' if r.get('is_tor') else '—'}</td>
        </tr>"""

    return f"""
    <section>
        <h2>🌐 Threat Intelligence</h2>
        <table>
            <thead><tr><th>IP</th><th>Abuse Score</th><th>Risk</th><th>Country</th><th>ISP</th><th>Reports</th><th>TOR</th></tr></thead>
            <tbody>{rows}</tbody>
        </table>
    </section>"""


# ── HTML wrapper ──────────────────────────────────────────────────────────────

def _wrap_page(generated_at: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CyberSentry Report — {generated_at}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --accent: #58a6ff; --text: #c9d1d9; --muted: #8b949e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 2rem; }}
  header {{ display:flex; align-items:center; gap:1rem; margin-bottom:2rem; border-bottom:1px solid var(--border); padding-bottom:1rem; }}
  header h1 {{ font-size:1.8rem; color:var(--accent); }}
  header .meta {{ color:var(--muted); font-size:.85rem; }}
  section {{ background:var(--surface); border:1px solid var(--border); border-radius:8px; padding:1.5rem; margin-bottom:1.5rem; }}
  section h2 {{ font-size:1.2rem; margin-bottom:1rem; color:var(--accent); }}
  .meta-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(200px,1fr)); gap:.75rem; margin-bottom:1rem; }}
  .meta-item {{ background:var(--bg); border:1px solid var(--border); border-radius:6px; padding:.6rem .8rem; }}
  .meta-item label {{ display:block; color:var(--muted); font-size:.75rem; margin-bottom:.2rem; }}
  .meta-item span {{ font-weight:600; font-size:.9rem; }}
  table {{ width:100%; border-collapse:collapse; font-size:.875rem; }}
  th {{ background:var(--bg); color:var(--muted); text-align:left; padding:.6rem .8rem; border-bottom:1px solid var(--border); }}
  td {{ padding:.6rem .8rem; border-bottom:1px solid var(--border); vertical-align:top; }}
  tr:last-child td {{ border-bottom:none; }}
  .badge {{ display:inline-block; padding:.2rem .5rem; border-radius:4px; color:#fff; font-size:.75rem; font-weight:700; }}
  .badge.open {{ background:#27ae60; }}
  .banner {{ font-family:monospace; font-size:.75rem; color:var(--muted); max-width:300px; word-break:break-all; }}
  .error {{ color:#e74c3c; }}
  footer {{ text-align:center; color:var(--muted); font-size:.8rem; margin-top:2rem; }}
</style>
</head>
<body>
<header>
  <div>
    <h1>🛡️ CyberSentry Security Report</h1>
    <span class="meta">Generated: {generated_at}</span>
  </div>
</header>
{body}
<footer>Generated by CyberSentry &bull; github.com/yourusername/cybersentry</footer>
</body>
</html>"""


def _esc(text: str) -> str:
    """HTML-escape a string."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )
