# Setting Up Telegram Alerts

Get real-time threat alerts on your phone in under 5 minutes.

## Step 1 — Create a Telegram Bot

1. Open Telegram and search for **@BotFather**
2. Send `/newbot`
3. Choose a name: e.g. `My Sentinel Bot`
4. Choose a username: e.g. `my_sentinel_bot`
5. BotFather gives you a **token** like `7123456789:AAHxxx...`

## Step 2 — Get Your Chat ID

1. Start a conversation with your new bot (send `/start`)
2. Visit this URL in your browser:
   ```
   https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates
   ```
3. Find `"chat":{"id":123456789}` — that number is your **Chat ID**

## Step 3 — Configure Sentinel AI

Edit your `.env`:
```env
TELEGRAM_BOT_TOKEN=7123456789:AAHxxx...
TELEGRAM_CHAT_ID=123456789
```

## Step 4 — Test It

```bash
python -c "
import asyncio, os
from dotenv import load_dotenv
load_dotenv()
from alerts.telegram_alert import TelegramAlerter
alert = TelegramAlerter()
asyncio.run(alert.send({
    'risk': 'HIGH',
    'type': 'TEST',
    'source_ip': '1.2.3.4',
    'service': 'TEST',
    'count': 1,
    'timestamp': '2026-04-13T18:00:00',
    'ai_analysis': 'This is a test alert from Sentinel AI.',
    'remediation': 'No action needed — this is a test.',
}))
print('✅ Test alert sent!')
"
```

You should see a formatted alert on your Telegram.
