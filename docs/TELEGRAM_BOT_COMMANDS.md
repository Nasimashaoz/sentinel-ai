# Sentinel AI — Telegram Bot Commands

Once Sentinel AI is running, you can query it directly from Telegram.

## Available Commands

| Command | Description |
|---|---|
| `/status` | Agent uptime, host info, and 24h incident summary |
| `/report` | Last 24 hours — top 5 most recent incidents |
| `/top` | Top 5 most active attacker IPs |
| `/banip <ip>` | Add an IP to your local blocklist |
| `/unbanip <ip>` | Remove an IP from your blocklist |
| `/help` | Show all commands |

## Example Responses

**`/status`:**
```
🛡️ Sentinel AI — Status
💻 Host: prod-server-01
🕒 Time: 2026-04-13 18:00 UTC

📊 Last 24 hours:
   🚨 Critical: 3
   🔴 High: 7
   📌 Total: 14
   🔒 All time: 283
```

**`/banip 45.33.32.156`:**
```
⛔ IP 45.33.32.156 added to local blocklist.
   Future events from this IP will be flagged.
```

## Enabling the Bot

In `sentinel.py`, the bot is started alongside the main agent loop automatically when `TELEGRAM_BOT_TOKEN` is set. No extra config needed.
