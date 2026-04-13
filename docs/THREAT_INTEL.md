# Sentinel AI — Live Threat Intelligence

Every detected threat is automatically enriched with real-time IOC data from AbuseIPDB and VirusTotal before alerting.

## What Gets Checked

| Source | What it tells you | Free tier |
|---|---|---|
| **AbuseIPDB** | Abuse confidence %, report count, ISP, Tor exit node, country | 1,000 checks/day |
| **VirusTotal** | Detections by 70+ AV engines, reputation score, ASN | 4/min, 500/day |

## Setup

```env
# .env
ABUSEIPDB_API_KEY=your_key_here      # https://www.abuseipdb.com/api
VIRUSTOTAL_API_KEY=your_key_here     # https://www.virustotal.com/gui/my-apikey
THREAT_INTEL_CACHE_HOURS=24          # cache TTL (saves API quota)
THREAT_INTEL_MIN_SCORE=20            # AbuseIPDB % to flag as malicious
```

Both APIs are **free to sign up** — no credit card needed.

## What Happens on a Hit

1. Threat detected (e.g. SSH brute force from `45.33.32.156`)
2. Threat Intel Engine looks up the IP in cache → if stale, queries AbuseIPDB + VirusTotal in parallel
3. Results merged: `malicious=true` if abuse score ≥ 20% OR VirusTotal ≥ 3 engines flag it OR Tor exit node
4. If malicious → risk auto-escalated (LOW→HIGH, HIGH→CRITICAL)
5. Alert sent with enriched context:

```
🚨 CRITICAL: SSH Brute Force from 45.33.32.156
AbuseIPDB: 94% confidence (312 reports)
VirusTotal: 8/93 engines flagged malicious
ISP: Linode LLC | Country: US | Tor: No
Risk escalated: AbuseIPDB score 94% (312 reports)
```

## Cache

Results cached to `data/threat_intel_cache.json` for 24 hours to stay within free API limits. Delete the file to force a fresh lookup.
