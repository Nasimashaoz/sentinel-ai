"""
Sentinel AI — Discord Alert Channel
Sends rich embed alerts to a Discord channel via webhook.
"""

import logging
import os
import aiohttp
from datetime import datetime

log = logging.getLogger(__name__)

RISK_COLOR = {
    "CRITICAL": 0xEF4444,  # red
    "HIGH":     0xF97316,  # orange
    "MEDIUM":   0xEAB308,  # yellow
    "LOW":      0x22C55E,  # green
}
RISK_EMOJI = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


class DiscordAlerter:
    def __init__(self):
        self.webhook = os.getenv("DISCORD_WEBHOOK_URL")

    async def send(self, threat: dict):
        risk = threat.get("risk", "HIGH")
        t_type = threat.get("type", "UNKNOWN").replace("_", " ")
        emoji = RISK_EMOJI.get(risk, "🚨")
        color = RISK_COLOR.get(risk, 0xEF4444)

        fields = [
            {"name": "🎯 Risk",      "value": f"`{risk}`",                              "inline": True},
            {"name": "💻 Source IP", "value": f"`{threat.get('source_ip', 'unknown')}`",  "inline": True},
            {"name": "⚙️ Service",   "value": threat.get("service", "N/A"),              "inline": True},
            {"name": "📊 Count",     "value": str(threat.get("count", "N/A")),           "inline": True},
        ]
        if threat.get("ai_analysis"):
            fields.append({"name": "🧠 AI Analysis",  "value": threat["ai_analysis"][:1024], "inline": False})
        if threat.get("remediation"):
            fields.append({"name": "✅ Remediation", "value": f"```{threat['remediation']}```",  "inline": False})

        payload = {
            "embeds": [{
                "title": f"{emoji} {risk}: {t_type}",
                "color": color,
                "fields": fields,
                "footer": {"text": "Sentinel AI • github.com/Nasimashaoz/sentinel-ai"},
                "timestamp": threat.get("timestamp", datetime.utcnow().isoformat()),
            }]
        }

        async with aiohttp.ClientSession() as session:
            resp = await session.post(self.webhook, json=payload)
            if resp.status not in (200, 204):
                text = await resp.text()
                log.error(f"Discord alert failed {resp.status}: {text}")
            else:
                log.info(f"Discord alert sent: {t_type}")
