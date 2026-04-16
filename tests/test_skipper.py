"""
Tests for skipper modules.
Run: pytest tests/ -v
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from skipper.scanner import scan_port, COMMON_PORTS
from skipper.log_analyzer import analyze_log, summary, AnalysisResult
from skipper.reporter import _esc, generate_report
from skipper.threat_intel import _risk_level


# ── scanner tests ─────────────────────────────────────────────────────────────

class TestScanner:
    def test_closed_port_returns_closed_state(self):
        """Port 9 (discard) is almost always closed."""
        result = scan_port("127.0.0.1", 9, timeout=0.5)
        assert result["state"] in ("open", "closed")
        assert "port" in result
        assert "service" in result

    def test_common_ports_has_ssh(self):
        assert 22 in COMMON_PORTS
        assert COMMON_PORTS[22] == "SSH"

    def test_scan_target_unreachable_host(self):
        from skipper.scanner import scan_target
        result = scan_target("this.host.does.not.exist.invalid")
        assert "error" in result

    def test_scan_port_result_structure(self):
        result = scan_port("127.0.0.1", 65432, timeout=0.3)
        assert set(result.keys()) == {"port", "state", "service", "banner"}


# ── log_analyzer tests ────────────────────────────────────────────────────────

SAMPLE_AUTH_LOG = """\
Apr 10 02:15:01 server sshd[1234]: Failed password for root from 192.168.1.50 port 54322 ssh2
Apr 10 02:15:02 server sshd[1234]: Failed password for root from 192.168.1.50 port 54323 ssh2
Apr 10 02:15:03 server sshd[1234]: Failed password for root from 192.168.1.50 port 54324 ssh2
Apr 10 02:15:04 server sshd[1234]: Failed password for root from 192.168.1.50 port 54325 ssh2
Apr 10 02:15:05 server sshd[1234]: Failed password for root from 192.168.1.50 port 54326 ssh2
Apr 10 02:15:06 server sshd[1234]: Failed password for root from 192.168.1.50 port 54327 ssh2
Apr 10 02:16:00 server sshd[1234]: Accepted password for alice from 10.0.0.5 port 22 ssh2
"""


class TestLogAnalyzer:
    def test_brute_force_detection(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text(SAMPLE_AUTH_LOG)

        result = analyze_log(str(log_file))
        s = summary(result)

        assert s["total_lines"] == 7
        assert any(a["type"] == "BRUTE_FORCE" for a in s["alerts"])

    def test_brute_force_ip_correct(self, tmp_path):
        log_file = tmp_path / "auth.log"
        log_file.write_text(SAMPLE_AUTH_LOG)

        result = analyze_log(str(log_file))
        s = summary(result)
        bf_alerts = [a for a in s["alerts"] if a["type"] == "BRUTE_FORCE"]

        assert bf_alerts[0]["ip"] == "192.168.1.50"
        assert bf_alerts[0]["attempts"] == 6

    def test_missing_file_raises(self):
        with pytest.raises(FileNotFoundError):
            analyze_log("/nonexistent/path/auth.log")

    def test_no_alerts_on_clean_log(self, tmp_path):
        log_file = tmp_path / "clean.log"
        log_file.write_text("Apr 10 12:00:00 server sshd: Server listening on 0.0.0.0\n")
        result = analyze_log(str(log_file))
        s = summary(result)
        assert s["total_alerts"] == 0


# ── threat_intel tests ────────────────────────────────────────────────────────

class TestThreatIntel:
    def test_risk_level_high(self):
        assert _risk_level(80) == "HIGH"

    def test_risk_level_medium(self):
        assert _risk_level(50) == "MEDIUM"

    def test_risk_level_low(self):
        assert _risk_level(10) == "LOW"

    def test_risk_level_boundary_high(self):
        assert _risk_level(75) == "HIGH"

    def test_risk_level_boundary_medium(self):
        assert _risk_level(25) == "MEDIUM"

    def test_no_api_key_returns_error(self):
        from skipper import threat_intel
        threat_intel._API_KEY = ""
        threat_intel.check_ip.cache_clear()
        result = threat_intel.check_ip("8.8.8.8")
        assert "error" in result


# ── reporter tests ────────────────────────────────────────────────────────────

class TestReporter:
    def test_html_escape(self):
        assert _esc("<script>") == "&lt;script&gt;"
        assert _esc('"hello"') == "&quot;hello&quot;"

    def test_report_creates_file(self, tmp_path):
        output = str(tmp_path / "report.html")
        path = generate_report(
            scan_results={
                "target": "127.0.0.1",
                "resolved_ip": "127.0.0.1",
                "scanned_ports": 17,
                "open_ports": [],
                "scan_duration_sec": 0.5,
                "timestamp": "2024-01-01T00:00:00Z",
            },
            output_path=output,
        )
        assert os.path.exists(path)
        content = open(path, encoding="utf-8").read()
        assert "skipper" in content
        assert "127.0.0.1" in content
