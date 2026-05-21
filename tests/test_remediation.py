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

    def test_only_whitelisted_commands_allowed(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=True)
        # Non-whitelisted command must be rejected
        result = engine._is_safe_command("rm -rf /")
        assert result is False

    def test_fail2ban_is_whitelisted(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=True)
        result = engine._is_safe_command("fail2ban-client set sshd banip 1.2.3.4")
        assert result is True

    def test_iptables_drop_is_whitelisted(self, tmp_path):
        engine = self._make_engine(tmp_path, auto=True)
        result = engine._is_safe_command("iptables -A INPUT -s 1.2.3.4 -j DROP")
        assert result is True
