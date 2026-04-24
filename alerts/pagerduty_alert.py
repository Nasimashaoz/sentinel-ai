"""
Sentinel AI — PagerDuty Alert Channel
Triggers PagerDuty incidents for CRITICAL and HIGH threats.
Auto-resolves when the same incident type clears.

Requires: PAGERDUTY_ROUTING_KEY (Events API v2 integration key)
"""

import logging
import os
import hashlib
from datetime import datetime, timezone
import aiohttp

log = logging.getLogger(__name__)

SEVERITY_MAP = {"CRITICAL": "critical", "HIGH": "error", "MEDIUM": "warning", "LOW": "info"}


class PagerDutyAlerter:
    def __init__(self):
        self.routing_key = os.getenv("PAGERDUTY_ROUTING_KEY")
        self.only_critical = os.getenv("PAGERDUTY_CRITICAL_ONLY", "true").lower() == "true"

    def _dedup_key(self, threat: dict) -> str:
        """Stable dedup key so PagerDuty groups repeated same-type incidents."""
        raw = f"{threat.get('type')}-{threat.get('source_ip')}-{threat.get('service')}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    async def send(self, threat: dict):
        risk = threat.get("risk", "HIGH")
        if self.only_critical and risk not in ("CRITICAL", "HIGH"):
            return

        t_type = threat.get("type", "UNKNOWN").replace("_", " ")
        severity = SEVERITY_MAP.get(risk, "error")

        payload = {
            "routing_key": self.routing_key,
            "event_action": "trigger",
            "dedup_key": self._dedup_key(threat),
            "payload": {
                "summary": f"{risk}: {t_type} from {threat.get('source_ip', 'unknown')}",
                "severity": severity,
                "source": threat.get("service", "sentinel-ai"),
                "timestamp": threat.get("timestamp", datetime.now(timezone.utc).isoformat()),
                "custom_details": {
                    "risk": risk,
                    "source_ip": threat.get("source_ip"),
                    "service": threat.get("service"),
                    "count": threat.get("count"),
                    "ai_analysis": threat.get("ai_analysis", ""),
                    "remediation": threat.get("remediation", ""),
                }
            },
            "links": [{"href": "http://localhost:8080", "text": "Sentinel AI Dashboard"}],
        }

        async with aiohttp.ClientSession() as session:
            resp = await session.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=payload,
            )
            if resp.status == 202:
                log.info(f"PagerDuty incident triggered: {t_type}")
            else:
                text = await resp.text()
                log.error(f"PagerDuty failed {resp.status}: {text}")
