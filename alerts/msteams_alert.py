"""
Sentinel AI — Microsoft Teams Alert Channel
Sends adaptive card alerts via Teams incoming webhook.
"""

import logging
import os
import aiohttp

log = logging.getLogger(__name__)

RISK_COLOR = {"CRITICAL": "attention", "HIGH": "warning", "MEDIUM": "accent", "LOW": "good"}


class MSTeamsAlerter:
    def __init__(self):
        self.webhook = os.getenv("MSTEAMS_WEBHOOK_URL")

    async def send(self, threat: dict):
        risk = threat.get("risk", "HIGH")
        t_type = threat.get("type", "UNKNOWN").replace("_", " ")
        color = RISK_COLOR.get(risk, "attention")

        facts = [
            {"title": "Risk",      "value": risk},
            {"title": "Type",      "value": t_type},
            {"title": "Source IP", "value": threat.get("source_ip", "unknown")},
            {"title": "Service",   "value": threat.get("service", "N/A")},
            {"title": "Time",      "value": threat.get("timestamp", "N/A")},
        ]
        if threat.get("ai_analysis"):
            facts.append({"title": "AI Analysis", "value": threat["ai_analysis"]})
        if threat.get("remediation"):
            facts.append({"title": "Remediation", "value": threat["remediation"]})

        # Adaptive Card payload for Teams
        payload = {
            "type": "message",
            "attachments": [{
                "contentType": "application/vnd.microsoft.card.adaptive",
                "content": {
                    "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                    "type": "AdaptiveCard",
                    "version": "1.4",
                    "body": [
                        {
                            "type": "TextBlock",
                            "text": f"🛡️ Sentinel AI — {risk}: {t_type}",
                            "weight": "Bolder",
                            "size": "Medium",
                            "color": color,
                        },
                        {
                            "type": "FactSet",
                            "facts": facts,
                        }
                    ]
                }
            }]
        }

        async with aiohttp.ClientSession() as session:
            resp = await session.post(self.webhook, json=payload)
            if resp.status not in (200, 202):
                log.error(f"MS Teams alert failed: {resp.status}")
            else:
                log.info(f"MS Teams alert sent: {t_type}")
