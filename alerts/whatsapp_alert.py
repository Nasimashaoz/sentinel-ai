"""
Sentinel AI — WhatsApp Alert Channel (via Twilio)
"""

import logging
import os

log = logging.getLogger(__name__)

RISK_EMOJI = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}


class WhatsAppAlerter:
    def __init__(self):
        self.sid = os.getenv("WHATSAPP_ACCOUNT_SID")
        self.token = os.getenv("WHATSAPP_AUTH_TOKEN")
        self.from_ = os.getenv("WHATSAPP_FROM", "whatsapp:+14155238886")
        self.to = os.getenv("WHATSAPP_TO")

    async def send(self, threat: dict):
        try:
            from twilio.rest import Client
            import asyncio

            risk = threat.get("risk", "HIGH")
            t_type = threat.get("type", "UNKNOWN").replace("_", " ")
            emoji = RISK_EMOJI.get(risk, "🚨")

            msg = (
                f"{emoji} SENTINEL AI ALERT\n"
                f"{risk}: {t_type}\n"
                f"Source: {threat.get('source_ip', 'unknown')}\n"
                f"Time: {threat.get('timestamp', 'N/A')}\n"
            )
            if threat.get("ai_analysis"):
                msg += f"\nAnalysis: {threat['ai_analysis'][:200]}"
            if threat.get("remediation"):
                msg += f"\n\nFix: {threat['remediation']}"

            client = Client(self.sid, self.token)
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: client.messages.create(body=msg, from_=self.from_, to=self.to)
            )
            log.info(f"WhatsApp alert sent: {t_type}")
        except ImportError:
            log.error("twilio not installed. Run: pip install twilio")
        except Exception as e:
            log.error(f"WhatsApp alert failed: {e}")
