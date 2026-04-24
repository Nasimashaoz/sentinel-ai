"""
Sentinel AI — Interactive Telegram Bot
Allows querying Sentinel AI status, getting reports, and banning IPs directly from Telegram.

Commands:
  /status   — show agent status and last 24h stats
  /report   — get today's incident summary
  /top      — show top 5 attacker IPs
  /banip <ip>    — add IP to local blocklist
  /unbanip <ip>  — remove IP from blocklist
  /help     — show all commands
"""

import asyncio
import logging
import os
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
import aiohttp

log = logging.getLogger(__name__)


class TelegramBot:
    def __init__(self, agent=None):
        self.token = os.getenv("TELEGRAM_BOT_TOKEN")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID")
        self.api = f"https://api.telegram.org/bot{self.token}"
        self.agent = agent  # Reference to SentinelAgent for stats
        self.last_update_id = 0
        self.running = False
        self.data_file = Path("data/incidents.json")

    async def start_polling(self):
        """Poll for Telegram commands and respond."""
        if not self.token:
            return
        self.running = True
        log.info("🤖 Telegram bot polling started")
        while self.running:
            try:
                await self._poll_once()
            except Exception as e:
                log.debug(f"Bot poll error: {e}")
            await asyncio.sleep(3)

    async def _poll_once(self):
        params = {"offset": self.last_update_id + 1, "timeout": 2, "allowed_updates": ["message"]}
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{self.api}/getUpdates", params=params) as resp:
                if resp.status != 200:
                    return
                data = await resp.json()
                for update in data.get("result", []):
                    self.last_update_id = update["update_id"]
                    msg = update.get("message", {})
                    text = msg.get("text", "").strip()
                    chat_id = msg.get("chat", {}).get("id")
                    # Security: only respond to configured chat
                    if str(chat_id) != str(self.chat_id):
                        continue
                    await self._handle_command(text, chat_id)

    async def _handle_command(self, text: str, chat_id: int):
        if text.startswith("/status"):
            reply = self._cmd_status()
        elif text.startswith("/report"):
            reply = self._cmd_report()
        elif text.startswith("/top"):
            reply = self._cmd_top()
        elif text.startswith("/banip"):
            parts = text.split()
            ip = parts[1] if len(parts) > 1 else None
            reply = self._cmd_banip(ip)
        elif text.startswith("/unbanip"):
            parts = text.split()
            ip = parts[1] if len(parts) > 1 else None
            reply = self._cmd_unbanip(ip)
        elif text.startswith("/help") or text.startswith("/start"):
            reply = self._cmd_help()
        else:
            return  # ignore non-commands
        await self._send(reply, chat_id)

    def _load_incidents(self) -> list:
        if self.data_file.exists():
            try:
                return json.loads(self.data_file.read_text())
            except Exception:
                return []
        return []

    def _cmd_status(self) -> str:
        incidents = self._load_incidents()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        last_24h = [i for i in incidents if self._after(i.get("timestamp", ""), cutoff)]
        critical = sum(1 for i in last_24h if i.get("risk") == "CRITICAL")
        high = sum(1 for i in last_24h if i.get("risk") == "HIGH")
        return (
            f"🛡️ *Sentinel AI — Status*\n"
            f"💻 Host: `{os.uname().nodename}`\n"
            f"🕒 Time: `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}`\n\n"
            f"📊 *Last 24 hours:*\n"
            f"   🚨 Critical: {critical}\n"
            f"   🔴 High: {high}\n"
            f"   📌 Total: {len(last_24h)}\n"
            f"   🔒 All time: {len(incidents)}"
        )

    def _cmd_report(self) -> str:
        incidents = self._load_incidents()
        cutoff = datetime.now(timezone.utc) - timedelta(hours=24)
        last_24h = sorted(
            [i for i in incidents if self._after(i.get("timestamp", ""), cutoff)],
            key=lambda x: x.get("timestamp", ""), reverse=True
        )[:5]
        if not last_24h:
            return "🟢 No incidents in the last 24 hours. Your server is clean!"
        lines = ["📊 *Last 24h Incidents (top 5):*\n"]
        for i in last_24h:
            lines.append(
                f"🔹 `{i.get('timestamp','')[:16]}` — "
                f"*{i.get('risk')}* {i.get('type','').replace('_',' ')} "
                f"from `{i.get('source_ip','?')}`"
            )
        return "\n".join(lines)

    def _cmd_top(self) -> str:
        incidents = self._load_incidents()
        counts: dict = {}
        for i in incidents:
            ip = i.get("source_ip", "unknown")
            counts[ip] = counts.get(ip, 0) + 1
        top = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:5]
        if not top:
            return "🟢 No incidents recorded yet."
        lines = ["🎯 *Top 5 Attacker IPs:*\n"]
        for rank, (ip, count) in enumerate(top, 1):
            lines.append(f"  {rank}. `{ip}` — {count} incidents")
        return "\n".join(lines)

    def _cmd_banip(self, ip: str) -> str:
        if not ip:
            return "⚠️ Usage: `/banip <ip_address>`"
        try:
            from core.threat_intel import ThreatIntel
            ThreatIntel().add_to_blocklist(ip)
        except Exception:
            pass
        return f"⛔ IP `{ip}` added to local blocklist. Future events from this IP will be flagged."

    def _cmd_unbanip(self, ip: str) -> str:
        if not ip:
            return "⚠️ Usage: `/unbanip <ip_address>`"
        from core.threat_intel import _local_blocklist
        _local_blocklist.discard(ip)
        return f"✅ IP `{ip}` removed from local blocklist."

    def _cmd_help(self) -> str:
        return (
            "🛡️ *Sentinel AI Bot Commands*\n\n"
            "`/status`   — Agent status + 24h stats\n"
            "`/report`   — Last 24h incident summary\n"
            "`/top`      — Top 5 attacker IPs\n"
            "`/banip <ip>`    — Block an IP\n"
            "`/unbanip <ip>`  — Unblock an IP\n"
            "`/help`     — Show this message"
        )

    async def _send(self, text: str, chat_id: int):
        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{self.api}/sendMessage",
                json={"chat_id": chat_id, "text": text, "parse_mode": "Markdown"},
            )

    def _after(self, ts_str: str, cutoff: datetime) -> bool:
        try:
            dt = datetime.fromisoformat(ts_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt >= cutoff
        except Exception:
            return False
