"""
Sentinel AI — Tests for ReportGenerator
"""

import sys
import tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from reports.generator import ReportGenerator


def test_empty_report_html():
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = ReportGenerator(data_dir=tmpdir)
        html = gen.generate_html_report(days=7)
        assert "Sentinel AI" in html
        assert "No incidents" in html


def test_save_incident_and_report():
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = ReportGenerator(data_dir=tmpdir)
        gen.save_incident({
            "risk": "HIGH",
            "type": "BRUTE_FORCE",
            "source_ip": "1.2.3.4",
            "service": "SSH",
            "count": 50,
            "timestamp": "2026-04-13T10:00:00",
            "ai_analysis": "Brute force from known scanner.",
            "remediation": "iptables -A INPUT -s 1.2.3.4 -j DROP",
        })
        report = gen.generate_json_report(days=7)
        assert report["total_incidents"] == 1
        assert report["by_risk"]["HIGH"] == 1


def test_json_report_structure():
    with tempfile.TemporaryDirectory() as tmpdir:
        gen = ReportGenerator(data_dir=tmpdir)
        report = gen.generate_json_report()
        assert "generated_at" in report
        assert "total_incidents" in report
        assert "by_risk" in report
        assert "incidents" in report


if __name__ == "__main__":
    test_empty_report_html()
    test_save_incident_and_report()
    test_json_report_structure()
    print("✅ All report tests passed")
