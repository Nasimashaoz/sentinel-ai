# Setting Up Discord Alerts

## Step 1 — Create a Webhook

1. Open Discord, go to your server
2. Right-click the channel you want alerts in → **Edit Channel**
3. Go to **Integrations → Webhooks → New Webhook**
4. Name it `Sentinel AI`, optionally set an avatar
5. Click **Copy Webhook URL**

## Step 2 — Configure Sentinel AI

```env
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/xxx/yyy
```

## Step 3 — Enable in sentinel.py

Add to `sentinel.py` (already supported in v1.1+):
```python
if os.getenv("DISCORD_WEBHOOK_URL"):
    from alerts.discord_alert import DiscordAlerter
    alerters.append(DiscordAlerter())
```

## Step 4 — Test It

```bash
python -c "
import asyncio
from dotenv import load_dotenv; load_dotenv()
from alerts.discord_alert import DiscordAlerter
asyncio.run(DiscordAlerter().send({
    'risk': 'CRITICAL', 'type': 'BRUTE_FORCE',
    'source_ip': '45.33.32.156', 'service': 'SSH',
    'count': 847, 'timestamp': '2026-04-13T18:00:00',
    'ai_analysis': 'High-volume brute force from known Shodan scanner.',
    'remediation': 'iptables -A INPUT -s 45.33.32.156 -j DROP',
}))"
```
