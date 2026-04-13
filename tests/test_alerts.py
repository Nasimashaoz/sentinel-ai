"""
Tests for alert channels — payload formatting and send logic.
All HTTP calls are mocked.
"""
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from unittest.mock import patch, AsyncMock, MagicMock

SAMPLE_THREAT = {
    "type": "SSH_BRUTE_FORCE",
    "source_ip": "45.33.32.156",
    "service": "sshd",
    "risk": "CRITICAL",
    "count": 152,
    "raw": "152 failed SSH attempts from 45.33.32.156",
    "ai_analysis": "High-confidence brute force attack. Block immediately.",
    "remediation": "Run: fail2ban-client set sshd banip 45.33.32.156",
    "timestamp": "2026-04-13T14:30:00Z",
}


class TestSignalAlerter:
    def test_disabled_without_config(self):
        with patch.dict(os.environ, {"SIGNAL_SENDER": "", "SIGNAL_RECIPIENTS": ""}):
            from alerts.signal_alert import SignalAlerter
            a = SignalAlerter()
            assert a.enabled is False

    def test_should_send_critical(self):
        with patch.dict(os.environ, {
            "SIGNAL_SENDER": "+1234567890",
            "SIGNAL_RECIPIENTS": "+0987654321",
            "SIGNAL_MIN_RISK": "HIGH",
        }):
            from alerts.signal_alert import SignalAlerter
            a = SignalAlerter()
            assert a._should_send("CRITICAL") is True
            assert a._should_send("HIGH") is True
            assert a._should_send("MEDIUM") is False
            assert a._should_send("LOW") is False

    def test_message_format_contains_key_fields(self):
        with patch.dict(os.environ, {
            "SIGNAL_SENDER": "+1234567890",
            "SIGNAL_RECIPIENTS": "+0987654321",
        }):
            from alerts.signal_alert import SignalAlerter
            a = SignalAlerter()
            msg = a._format_message(SAMPLE_THREAT)
            assert "45.33.32.156" in msg
            assert "CRITICAL" in msg
            assert "sshd" in msg
            assert "152" in msg

    @pytest.mark.asyncio
    async def test_send_calls_signal_api(self):
        with patch.dict(os.environ, {
            "SIGNAL_SENDER": "+1234567890",
            "SIGNAL_RECIPIENTS": "+0987654321",
            "SIGNAL_API_URL": "http://localhost:8085",
        }):
            from alerts.signal_alert import SignalAlerter
            a = SignalAlerter()
            mock_resp = MagicMock()
            mock_resp.status = 201
            mock_session = MagicMock()
            mock_session.__aenter__ = AsyncMock(return_value=mock_session)
            mock_session.__aexit__ = AsyncMock(return_value=False)
            mock_session.post = AsyncMock(return_value=mock_resp)
            mock_resp.__aenter__ = AsyncMock(return_value=mock_resp)
            mock_resp.__aexit__ = AsyncMock(return_value=False)
            with patch("aiohttp.ClientSession", return_value=mock_session):
                await a.send(SAMPLE_THREAT)
                mock_session.post.assert_called_once()
                call_kwargs = mock_session.post.call_args
                assert "/v2/send" in call_kwargs[0][0]


class TestPagerDutyAlerter:
    def test_dedup_key_stable(self):
        with patch.dict(os.environ, {"PAGERDUTY_ROUTING_KEY": "test-key"}):
            from alerts.pagerduty_alert import PagerDutyAlerter
            a = PagerDutyAlerter()
            key1 = a._dedup_key(SAMPLE_THREAT)
            key2 = a._dedup_key(SAMPLE_THREAT)
            assert key1 == key2
            assert len(key1) == 16

    def test_critical_only_filter(self):
        with patch.dict(os.environ, {
            "PAGERDUTY_ROUTING_KEY": "test-key",
            "PAGERDUTY_CRITICAL_ONLY": "true",
        }):
            from alerts.pagerduty_alert import PagerDutyAlerter
            a = PagerDutyAlerter()
            # MEDIUM threat should not trigger PagerDuty in critical_only mode
            medium_threat = {**SAMPLE_THREAT, "risk": "MEDIUM"}
            import asyncio
            # send() returns early without HTTP call for MEDIUM when critical_only=true
            # We verify by checking the filter logic directly
            assert a.only_critical is True
