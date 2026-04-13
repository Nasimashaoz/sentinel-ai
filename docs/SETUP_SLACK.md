# Setting Up Slack Alerts

## Step 1 — Create an Incoming Webhook

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. Click **Create New App → From scratch**
3. Name it `Sentinel AI`, pick your workspace
4. Go to **Incoming Webhooks → Activate**
5. Click **Add New Webhook to Workspace**
6. Choose the channel (e.g. `#security-alerts`)
7. Copy the webhook URL: `https://hooks.slack.com/services/T.../B.../xxx`

## Step 2 — Configure Sentinel AI

Edit your `.env`:
```env
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../xxx
```

## Step 3 — Test It

```bash
python -c "
import asyncio
from dotenv import load_dotenv
load_dotenv()
from alerts.slack_alert import SlackAlerter
alert = SlackAlerter()
asyncio.run(alert.send({
    'risk': 'HIGH',
    'type': 'BRUTE_FORCE',
    'source_ip': '45.33.32.156',
    'service': 'SSH',
    'count': 250,
    'timestamp': '2026-04-13T18:00:00',
    'ai_analysis': 'High-volume brute force from known scanner.',
    'remediation': 'Run: fail2ban-client set sshd banip 45.33.32.156',
}))
print('✅ Slack alert sent!')
"
```
