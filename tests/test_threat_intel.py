"""
Tests for ThreatIntelEngine — AbuseIPDB + VirusTotal enrichment
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from pathlib import Path

import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestThreatIntelPrivateIPs:
    """Private / loopback IPs must never be looked up."""

    def _make_engine(self):
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}):
            from core.threat_intel import ThreatIntelEngine
            return ThreatIntelEngine()

    @pytest.mark.asyncio
    async def test_private_ip_skipped(self):
        engine = self._make_engine()
        threat = {"source_ip": "192.168.1.100", "risk": "HIGH", "type": "SSH_BRUTE_FORCE"}
        result = await engine.enrich(threat)
        assert "threat_intel" not in result

    @pytest.mark.asyncio
    async def test_loopback_skipped(self):
        engine = self._make_engine()
        threat = {"source_ip": "127.0.0.1", "risk": "HIGH", "type": "TEST"}
        result = await engine.enrich(threat)
        assert "threat_intel" not in result

    @pytest.mark.asyncio
    async def test_unknown_skipped(self):
        engine = self._make_engine()
        threat = {"source_ip": "unknown", "risk": "MEDIUM", "type": "TEST"}
        result = await engine.enrich(threat)
        assert "threat_intel" not in result


class TestThreatIntelMerge:
    """Risk escalation and intel merging logic."""

    def _make_engine(self):
        with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}):
            from core.threat_intel import ThreatIntelEngine
            return ThreatIntelEngine()

    def test_merge_malicious_abuse(self):
        engine = self._make_engine()
        abuse = {"abuse_score": 85, "abuse_reports": 200, "abuse_country": "RU",
                 "abuse_isp": "HostSailor", "abuse_is_tor": False, "abuse_is_whitelisted": False}
        vt = {"vt_malicious": 5, "vt_suspicious": 2, "vt_country": "RU",
              "vt_as_owner": "HostSailor", "vt_reputation": -50}
        result = engine._merge_intel("1.2.3.4", abuse, vt)
        assert result["malicious"] is True
        assert "AbuseIPDB" in result["reason"]
        assert "VirusTotal" in result["reason"]
        assert result["is_tor"] is False

    def test_merge_tor_node(self):
        engine = self._make_engine()
        abuse = {"abuse_score": 5, "abuse_reports": 1, "abuse_country": "US",
                 "abuse_isp": "", "abuse_is_tor": True, "abuse_is_whitelisted": False}
        result = engine._merge_intel("5.6.7.8", abuse, {})
        assert result["malicious"] is True
        assert "Tor" in result["reason"]

    def test_merge_clean_ip(self):
        engine = self._make_engine()
        abuse = {"abuse_score": 0, "abuse_reports": 0, "abuse_is_tor": False,
                 "abuse_country": "DE", "abuse_isp": "Hetzner", "abuse_is_whitelisted": False}
        vt = {"vt_malicious": 0, "vt_suspicious": 0, "vt_country": "DE"}
        result = engine._merge_intel("10.0.0.1", abuse, vt)
        assert result["malicious"] is False
        assert result["reason"] == "clean"

    @pytest.mark.asyncio
    async def test_risk_escalated_medium_to_high(self):
        engine = self._make_engine()
        malicious_intel = {"malicious": True, "reason": "AbuseIPDB score 90% (500 reports)",
                           "country": "CN", "isp": "China Telecom", "is_tor": False}
        with patch.object(engine, "_lookup_ip", new=AsyncMock(return_value=malicious_intel)):
            threat = {"source_ip": "8.8.8.8", "risk": "MEDIUM", "type": "PORT_SCAN"}
            result = await engine.enrich(threat)
            assert result["risk"] == "HIGH"
            assert "risk_escalated" in result

    @pytest.mark.asyncio
    async def test_risk_escalated_high_to_critical(self):
        engine = self._make_engine()
        malicious_intel = {"malicious": True, "reason": "VirusTotal 10 engines"}
        with patch.object(engine, "_lookup_ip", new=AsyncMock(return_value=malicious_intel)):
            threat = {"source_ip": "8.8.4.4", "risk": "HIGH", "type": "SSH_BRUTE_FORCE"}
            result = await engine.enrich(threat)
            assert result["risk"] == "CRITICAL"


class TestThreatIntelCache:
    """Cache read / write / TTL logic."""

    def _make_engine(self, tmp_path):
        with patch("core.threat_intel.CACHE_FILE", tmp_path / "cache.json"):
            with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}):
                from core.threat_intel import ThreatIntelEngine
                return ThreatIntelEngine()

    def test_cache_hit_returns_without_api_call(self, tmp_path):
        import time
        cache_data = {
            "1.2.3.4": {
                "ip": "1.2.3.4", "malicious": True, "reason": "test",
                "country": "US", "isp": "Test", "is_tor": False,
                "_cached_at": time.time(),
            }
        }
        cache_file = tmp_path / "cache.json"
        cache_file.write_text(json.dumps(cache_data))
        with patch("core.threat_intel.CACHE_FILE", cache_file):
            with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}):
                from core.threat_intel import ThreatIntelEngine
                engine = ThreatIntelEngine()
                result = engine._cache_get("1.2.3.4")
                assert result is not None
                assert result["malicious"] is True

    def test_cache_miss_on_expired(self, tmp_path):
        import time
        cache_data = {
            "1.2.3.4": {
                "ip": "1.2.3.4", "malicious": True,
                "_cached_at": time.time() - (25 * 3600),  # 25 hours ago
            }
        }
        cache_file = tmp_path / "cache.json"
        cache_file.write_text(json.dumps(cache_data))
        with patch("core.threat_intel.CACHE_FILE", cache_file):
            with patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "", "VIRUSTOTAL_API_KEY": ""}):
                from core.threat_intel import ThreatIntelEngine
                engine = ThreatIntelEngine()
                result = engine._cache_get("1.2.3.4")
                assert result is None
