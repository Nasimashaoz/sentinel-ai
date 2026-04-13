"""
Sentinel AI — Tests for ComplianceEngine
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.compliance import ComplianceEngine


def test_compliance_returns_dict():
    engine = ComplianceEngine()
    result = engine.run_all()
    assert isinstance(result, dict)
    assert "ssh_hardening" in result
    assert "firewall" in result
    assert "fail2ban" in result


def test_each_check_has_pass_and_findings():
    engine = ComplianceEngine()
    result = engine.run_all()
    for key, val in result.items():
        assert "pass" in val, f"Missing 'pass' in {key}"
        assert "findings" in val, f"Missing 'findings' in {key}"
        assert isinstance(val["findings"], list), f"'findings' not a list in {key}"


if __name__ == "__main__":
    test_compliance_returns_dict()
    test_each_check_has_pass_and_findings()
    print("✅ All compliance tests passed")
