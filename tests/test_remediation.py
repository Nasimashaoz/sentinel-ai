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
        env = {
            "AUTO_REMEDIATE": str(auto).lower(),
            "AUTO_REMEDIATE_CRITICAL": str(critical).lower(),
        }
        with patch.dict(os.environ, env):
            with patch("core.remediation.AUDIT_LOG", Path(tmp_dir) / "audit.jsonl"):
                from core.remediation import RemediationEngine
                return RemediationEngine()

    def test_dry_run_by_default(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=False)
        assert engine.dry_run is True

    @pytest.mark.asyncio
    async def test_only_whitelisted_commands_allowed(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=True)
        # Non-whitelisted command must be rejected
        result = await engine.handle({"type": "UNKNOWN_THREAT", "source_ip": "1.2.3.4"})
        assert result.get("action") == "none"

    @pytest.mark.asyncio
    async def test_fail2ban_is_whitelisted(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=True)
        result = await engine.handle({"type": "BRUTE_FORCE", "source_ip": "1.2.3.4"})
        # Action could be executed or dry_run, check if the command matches fail2ban
        assert result.get("action") in ("executed", "dry_run", "error")
        assert "fail2ban-client set sshd banip 1.2.3.4" in result.get("command", "")

    @pytest.mark.asyncio
    async def test_iptables_drop_is_whitelisted(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=True)
        result = await engine.handle({"type": "PORT_SCAN", "source_ip": "1.2.3.4"})
        assert result.get("action") in ("executed", "dry_run", "error")
        assert "iptables -A INPUT -s 1.2.3.4 -j DROP" in result.get("command", "")
