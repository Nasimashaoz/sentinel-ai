"""
Sentinel AI — Telegram Alert Channel
"""

import logging
import os
import aiohttp

log = logging.getLogger(__name__)

RISK_EMOJI = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
TYPE_EMOJI = {
    "BRUTE_FORCE": "🔐",
    "PORT_SCAN": "🔍",
    "WEB_SCAN": "🌐",
    "SUSPICIOUS_PROCESS": "⚠️",
    "FILE_CHANGE": "📁",
}


class TelegramAlerter:
    def __init__(self):
        self.token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID")
        self.api = f"https://api.telegram.org/bot{self.token}"

    async def send(self, threat: dict):
        risk = threat.get("risk", "HIGH")
        t_type = threat.get("type", "UNKNOWN")
        emoji = RISK_EMOJI.get(risk, "🚨")
        t_emoji = TYPE_EMOJI.get(t_type, "⚠️")

        msg = (
            f"{emoji} *{risk} THREAT DETECTED*\n"
            f"🗓 `{threat.get('timestamp', 'N/A')}`\n\n"
            f"{t_emoji} *{t_type.replace('_', ' ')}*\n"
            f"   Source: `{threat.get('source_ip', 'unknown')}`\n"
            f"   Service: {threat.get('service', 'N/A')}\n"
            f"   Count: {threat.get('count', 'N/A')}\n\n"
        )
        if threat.get("ai_analysis"):
            msg += f"🧠 *AI Analysis:*\n{threat['ai_analysis']}\n\n"
        if threat.get("remediation"):
            msg += f"✅ *Remediation:*\n`{threat['remediation']}`\n"

        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{self.api}/sendMessage",
                json={"chat_id": self.chat_id, "text": msg, "parse_mode": "Markdown"},
            )
        log.info(f"Telegram alert sent: {t_type} from {threat.get('source_ip')}")
