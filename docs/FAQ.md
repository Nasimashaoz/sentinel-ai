# Frequently Asked Questions

## Does Sentinel AI send my logs to the cloud?

**No.** Your logs never leave your server. The only external calls made are:
- Anthropic Claude API (threat analysis) — only the *event metadata*, never raw log lines
- Your chosen alert channel (Telegram/Slack/WhatsApp/Email)

To run fully offline, omit the `CLAUDE_API_KEY` — Sentinel AI falls back to local rule-based analysis.

## What permissions does Sentinel AI need?

Minimum required:
- Read access to `/var/log/auth.log` (or `/var/log/secure`)
- Read access to `/var/log/nginx/access.log` (if nginx monitoring enabled)
- Execute `ps aux` and `ss -tn`

Do **not** run as root. Create a dedicated user:
```bash
useradd -r -s /sbin/nologin sentinel
usermod -aG adm sentinel        # grants log read access on Ubuntu/Debian
chown sentinel /opt/sentinel-ai
```

## Does it work on macOS or Windows?

Sentinel AI is designed for **Linux** (Ubuntu, Debian, RHEL, CentOS, Arch). The log paths and `ss`/`ps` commands are Linux-specific. macOS support is planned for v2.0.

## How much CPU/RAM does it use?

Extremely light:
- **CPU:** < 0.5% average (polls every 10 seconds)
- **RAM:** ~40–60 MB Python process
- **Disk:** Only writes to `data/incidents.json` and `sentinel.log`

## What if the Claude API is down?

Sentinel AI **automatically falls back** to rule-based analysis. You still get alerts — they just won't have AI-generated explanations. The fallback is instant and requires no configuration.

## How do I add custom detection rules?

Edit `core/collector.py`. Each collector method returns a list of event dicts. Add your own pattern matching and return events in the same format:
```python
{"type": "MY_CUSTOM_EVENT", "source_ip": "...", "count": 1, "service": "...", "raw": "..."}
```
Then add a rule in `core/analyzer.py → _rule_based_check()` for instant risk classification.

## Can I monitor multiple servers?

v1.0 monitors the host it runs on. **v2.0 (planned)** will support a central collector with agents on remote hosts reporting back via a lightweight gRPC/HTTP protocol.
