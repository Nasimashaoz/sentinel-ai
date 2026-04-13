#!/usr/bin/env python3
"""
Sentinel AI — Your 24/7 Self-Hosted AI Security Agent
Main entry point
Author: Nasima Shaoz
License: MIT
"""

import asyncio
import logging
import os
import signal
import sys
from datetime import datetime
from dotenv import load_dotenv

from core.agent import SentinelAgent
from core.collector import LogCollector
from core.analyzer import ThreatAnalyzer
from alerts.telegram_alert import TelegramAlerter
from alerts.slack_alert import SlackAlerter
from alerts.whatsapp_alert import WhatsAppAlerter
from alerts.email_alert import EmailAlerter

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [→ SENTINEL] %(levelname)s: %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("sentinel.log"),
    ],
)
log = logging.getLogger(__name__)


def print_banner():
    print("""
┌──────────────────────────────────────────────┐
│  🛡️  SENTINEL AI  —  24/7 Security Agent     │
│  Version 1.0.0  │  github.com/Nasimashaoz  │
└──────────────────────────────────────────────┘
    """)


async def main():
    print_banner()
    log.info("Starting Sentinel AI agent...")

    # Initialize alerters based on config
    alerters = []
    if os.getenv("TELEGRAM_BOT_TOKEN"):
        alerters.append(TelegramAlerter())
        log.info("Telegram alerts: ENABLED")
    if os.getenv("SLACK_WEBHOOK_URL"):
        alerters.append(SlackAlerter())
        log.info("Slack alerts: ENABLED")
    if os.getenv("WHATSAPP_ACCOUNT_SID"):
        alerters.append(WhatsAppAlerter())
        log.info("WhatsApp alerts: ENABLED")
    if os.getenv("EMAIL_FROM"):
        alerters.append(EmailAlerter())
        log.info("Email alerts: ENABLED")

    if not alerters:
        log.warning("No alert channels configured. Check your .env file.")

    # Initialize components
    collector = LogCollector()
    analyzer = ThreatAnalyzer(api_key=os.getenv("CLAUDE_API_KEY"))
    agent = SentinelAgent(collector=collector, analyzer=analyzer, alerters=alerters)

    # Graceful shutdown
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, lambda: asyncio.ensure_future(agent.stop()))

    log.info(f"Sentinel AI is LIVE — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    log.info("Watching: SSH logs, nginx, syslog, processes, open ports")
    log.info("Press Ctrl+C to stop")

    await agent.run()


if __name__ == "__main__":
    asyncio.run(main())
