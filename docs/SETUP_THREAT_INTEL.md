# Setting Up Threat Intelligence Enrichment

Sentinel AI can enrich every attacker IP with real-time threat intelligence from AbuseIPDB and GreyNoise — for free.

## AbuseIPDB (Free tier: 1,000 checks/day)

1. Sign up at [abuseipdb.com](https://www.abuseipdb.com/register)
2. Go to **API → Create Key**
3. Copy your API key

```env
ABUSEIPDB_API_KEY=your_key_here
```

What you get per alert:
```
🚨 Known malicious (AbuseIPDB score: 97%, 2,847 reports)
🏳️ Country: CN | ISP: Alibaba Cloud
```

## GreyNoise (Free community tier)

1. Sign up at [greynoise.io](https://www.greynoise.io/)
2. Go to **Account → API Key**

```env
GREYNOISE_API_KEY=your_key_here
```

What you get:
```
🌐 GreyNoise: malicious scanner (Mirai)
```

This tells you if an IP is just background internet noise vs. a targeted attack — dramatically reducing false positives.

## Both disabled?

No problem — Sentinel AI works without either. Threat intel is purely additive enrichment.
