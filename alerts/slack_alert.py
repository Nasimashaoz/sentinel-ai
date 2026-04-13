"""
Sentinel AI — Slack Alert Channel
"""

import logging
import os
import aiohttp

log = logging.getLogger(__name__)

RISK_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}


class SlackAlerter:
    def __init__(self):
        self.webhook = os.getenv("SLACK_WEBHOOK_URL")

    async def send(self, threat: dict):
        risk = threat.get("risk", "HIGH")
        color = RISK_COLOR.get(risk, "#dc2626")
        t_type = threat.get("type", "UNKNOWN").replace("_", " ")

        fields = [
            {"title": "Risk", "value": risk, "short": True},
            {"title": "Source IP", "value": threat.get("source_ip", "unknown"), "short": True},
            {"title": "Service", "value": threat.get("service", "N/A"), "short": True},
            {"title": "Count", "value": str(threat.get("count", "N/A")), "short": True},
        ]
        if threat.get("ai_analysis"):
            fields.append({"title": "🧠 AI Analysis", "value": threat["ai_analysis"], "short": False})
        if threat.get("remediation"):
            fields.append({"title": "✅ Remediation", "value": threat["remediation"], "short": False})

        payload = {
            "attachments": [{
                "color": color,
                "title": f"🛡️ Sentinel AI — {risk}: {t_type}",
                "fields": fields,
                "footer": "Sentinel AI • github.com/Nasimashaoz/sentinel-ai",
                "ts": threat.get("timestamp", ""),
            }]
        }
        async with aiohttp.ClientSession() as session:
            await session.post(self.webhook, json=payload)
        log.info(f"Slack alert sent: {t_type}")
