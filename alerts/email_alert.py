"""
Sentinel AI — Email Alert Channel
"""

import asyncio
import logging
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

log = logging.getLogger(__name__)

RISK_COLOR = {"CRITICAL": "#dc2626", "HIGH": "#f97316", "MEDIUM": "#eab308", "LOW": "#22c55e"}


class EmailAlerter:
    def __init__(self):
        self.from_addr = os.getenv("EMAIL_FROM")
        self.to_addr = os.getenv("EMAIL_TO")
        self.smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        self.smtp_port = int(os.getenv("SMTP_PORT", 587))
        self.smtp_user = os.getenv("SMTP_USER", self.from_addr)
        self.smtp_pass = os.getenv("SMTP_PASS", "")

    async def send(self, threat: dict):
        risk = threat.get("risk", "HIGH")
        t_type = threat.get("type", "UNKNOWN").replace("_", " ")
        color = RISK_COLOR.get(risk, "#dc2626")

        html = f"""
        <html><body style="font-family:sans-serif;margin:0;padding:20px">
        <div style="border-left:4px solid {color};padding:20px;background:#f9f9f9">
        <h2 style="color:{color};margin:0">🛡️ Sentinel AI — {risk}: {t_type}</h2>
        <p><strong>Time:</strong> {threat.get('timestamp')}</p>
        <p><strong>Source IP:</strong> {threat.get('source_ip', 'unknown')}</p>
        <p><strong>Service:</strong> {threat.get('service', 'N/A')}</p>
        <p><strong>Count:</strong> {threat.get('count', 'N/A')}</p>
        {'<h3>AI Analysis</h3><p>' + threat['ai_analysis'] + '</p>' if threat.get('ai_analysis') else ''}
        {'<h3>Remediation</h3><code style="background:#eee;padding:8px;display:block">' + threat['remediation'] + '</code>' if threat.get('remediation') else ''}
        <hr><small>Sentinel AI • github.com/Nasimashaoz/sentinel-ai</small>
        </div></body></html>
        """

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"🚨 [{risk}] Sentinel AI: {t_type} detected"
        msg["From"] = self.from_addr
        msg["To"] = self.to_addr
        msg.attach(MIMEText(html, "html"))

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._send_smtp, msg)
        log.info(f"Email alert sent: {t_type}")

    def _send_smtp(self, msg):
        with smtplib.SMTP(self.smtp_host, self.smtp_port) as s:
            s.ehlo()
            s.starttls()
            s.login(self.smtp_user, self.smtp_pass)
            s.send_message(msg)
