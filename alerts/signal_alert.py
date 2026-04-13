"""
Sentinel AI — Signal Messenger Alert Channel
Sends threat alerts via Signal using signal-cli REST API.

Requires: signal-cli-rest-api running locally or remotely
  docker run -d -p 8080:8080 \
    -v $HOME/.local/share/signal-cli:/home/.local/share/signal-cli \
    bbernhard/signal-cli-rest-api

Env vars:
  SIGNAL_API_URL      = http://localhost:8085  (signal-cli REST API)
  SIGNAL_SENDER       = +1234567890            (your registered Signal number)
  SIGNAL_RECIPIENTS   = +0987654321,+1122334455 (comma-separated)
  SIGNAL_MIN_RISK     = HIGH                   (minimum risk level to alert)
"""

import logging
import os
import aiohttp

log = logging.getLogger(__name__)

RISK_EMOJI = {"CRITICAL": "🚨", "HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}


class SignalAlerter:
    def __init__(self):
        self.api_url = os.getenv("SIGNAL_API_URL", "http://localhost:8085").rstrip("/")
        self.sender = os.getenv("SIGNAL_SENDER", "")
        raw_recipients = os.getenv("SIGNAL_RECIPIENTS", "")
        self.recipients = [r.strip() for r in raw_recipients.split(",") if r.strip()]
        self.min_risk = os.getenv("SIGNAL_MIN_RISK", "HIGH")
        self.enabled = bool(self.sender and self.recipients)
        if self.enabled:
            log.info(f"✅ Signal alerter ready → {len(self.recipients)} recipient(s)")

    def _should_send(self, risk: str) -> bool:
        return RISK_ORDER.get(risk, 0) >= RISK_ORDER.get(self.min_risk, 2)

    def _format_message(self, threat: dict) -> str:
        risk = threat.get("risk", "HIGH")
        emoji = RISK_EMOJI.get(risk, "🔴")
        t_type = threat.get("type", "UNKNOWN").replace("_", " ").title()
        lines = [
            f"{emoji} *Sentinel AI — {risk} Alert*",
            f"*Type:* {t_type}",
            f"*Source IP:* {threat.get('source_ip', 'unknown')}",
            f"*Service:* {threat.get('service', 'unknown')}",
        ]
        if threat.get("count"):
            lines.append(f"*Count:* {threat['count']} events")
        if threat.get("ai_analysis"):
            lines.append(f"*AI Analysis:* {threat['ai_analysis'][:300]}")
        if threat.get("remediation"):
            lines.append(f"*Action:* {threat['remediation']}")
        lines.append(f"*Raw:* {str(threat.get('raw', ''))[:200]}")
        return "\n".join(lines)

    async def send(self, threat: dict):
        risk = threat.get("risk", "HIGH")
        if not self.enabled or not self._should_send(risk):
            return
        message = self._format_message(threat)
        payload = {
            "message": message,
            "number": self.sender,
            "recipients": self.recipients,
        }
        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.post(
                    f"{self.api_url}/v2/send",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=10),
                )
                if resp.status == 201:
                    log.info(f"Signal alert sent: {threat.get('type')}")
                else:
                    text = await resp.text()
                    log.warning(f"Signal API {resp.status}: {text[:200]}")
        except Exception as e:
            log.error(f"Signal alert error: {e}")
