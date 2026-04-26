"""
Tests for the auto-remediation engine.
Verifies dry-run default, whitelist enforcement, audit logging.
"""
import pytest
import sys, os
import json
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestRemediationSafety:
    def _make_engine(self, tmp_dir, auto=False, critical=False):
        with patch("core.remediation.AUDIT_LOG", Path(tmp_dir) / "audit.jsonl"):
            from core.remediation import RemediationEngine
            engine = RemediationEngine()
            engine.dry_run = not auto
            return engine

    def test_dry_run_by_default(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=False)
        assert engine.dry_run is True

    @pytest.mark.asyncio
    async def test_only_whitelisted_commands_allowed(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=True)
        threat = {
            "type": "UNKNOWN_THREAT",
            "risk": "HIGH",
            "source_ip": "1.2.3.4"
        }
        result = await engine.handle(threat)
        assert result["action"] == "none"
        assert "No playbook" in result["reason"]

    @pytest.mark.asyncio
    async def test_fail2ban_is_whitelisted(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=True)
        threat = {
            "type": "BRUTE_FORCE",
            "risk": "HIGH",
            "source_ip": "1.2.3.4"
        }
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""
            result = await engine.handle(threat)
            assert result["action"] == "executed"
            assert "fail2ban-client set sshd banip 1.2.3.4" in result["command"]

    @pytest.mark.asyncio
    async def test_iptables_drop_is_whitelisted(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=True)
        threat = {
            "type": "PORT_SCAN",
            "risk": "HIGH",
            "source_ip": "1.2.3.4"
        }
        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = ""
            mock_run.return_value.stderr = ""
            result = await engine.handle(threat)
            assert result["action"] == "executed"
            assert "iptables -A INPUT -s 1.2.3.4 -j DROP" in result["command"]
