# Setting Up WhatsApp Alerts

Get threat alerts sent directly to your WhatsApp.

## Prerequisites
- A free [Twilio account](https://www.twilio.com/try-twilio)

## Step 1 — Twilio Setup

1. Sign up at [twilio.com](https://www.twilio.com/try-twilio) (free trial gives $15 credit)
2. Go to **Console → Account Info**
3. Copy your **Account SID** and **Auth Token**

## Step 2 — Enable WhatsApp Sandbox

1. In Twilio Console, go to **Messaging → Try it Out → Send a WhatsApp Message**
2. Follow instructions to join the sandbox (send a code via WhatsApp to Twilio's number)
3. Your sandbox number is: `+1 415 523 8886`

## Step 3 — Configure Sentinel AI

Edit your `.env`:
```env
WHATSAPP_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
WHATSAPP_AUTH_TOKEN=your_auth_token_here
WHATSAPP_FROM=whatsapp:+14155238886
WHATSAPP_TO=whatsapp:+91XXXXXXXXXX   # Your number with country code
```

## Step 4 — Test It

```bash
python -c "
import asyncio
from dotenv import load_dotenv
load_dotenv()
from alerts.whatsapp_alert import WhatsAppAlerter
alert = WhatsAppAlerter()
asyncio.run(alert.send({
    'risk': 'CRITICAL',
    'type': 'TEST',
    'source_ip': '1.2.3.4',
    'service': 'SSH',
    'count': 100,
    'timestamp': '2026-04-13T18:00:00',
    'ai_analysis': 'Test alert from Sentinel AI.',
    'remediation': 'No action needed.',
}))
print('✅ WhatsApp alert sent!')
"
```

> **Note:** For production use, upgrade from Twilio sandbox to a dedicated WhatsApp number.
