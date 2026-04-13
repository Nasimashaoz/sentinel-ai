# Changelog

All notable changes to Sentinel AI are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-04-13

### 🎉 Initial Release

#### Added
- **Core agent loop** — async collect → analyze → score → alert pipeline
- **SSH brute force detection** — monitors `/var/log/auth.log` and `/var/log/secure`, alerts after configurable threshold
- **Nginx web scan detection** — detects probing and scanning via error response spikes
- **Suspicious process detection** — catches nmap, hydra, metasploit, reverse shells
- **Port scan detection** — monitors anomalous connection counts via `ss`
- **Claude AI threat analysis** — enriches every threat with natural-language explanation + exact remediation command
- **Rule-based fallback** — works without Claude API key using built-in rules
- **Risk scorer** — 0–100 numeric score per incident with volume-based boosting
- **Telegram alerter** — Markdown-formatted alerts via Bot API
- **Slack alerter** — Rich attachment format with color-coded risk levels
- **WhatsApp alerter** — Instant alerts via Twilio WhatsApp API
- **Email alerter** — HTML-formatted incident emails via SMTP
- **Alert deduplication** — configurable cooldown per threat type + source IP
- **Web dashboard** — Flask + SSE live threat feed, risk stat cards, top attacker IPs
- **Compliance engine** — automated SSH hardening, firewall, fail2ban, password policy checks
- **Report generator** — HTML and JSON audit reports with configurable date range
- **Docker support** — `docker-compose up -d` single-command deployment
- **One-line installer** — `curl | bash` VPS installer with systemd service registration
- **GitHub Actions CI** — syntax check + unit tests on every push
- **3 test suites** — scorer, compliance, report generator

---

## [Unreleased] — Coming in v1.1

- [ ] Interactive Telegram bot commands (`/status`, `/report`, `/banip`)
- [ ] Full web dashboard with incident detail pages
- [ ] AbuseIPDB integration for threat intelligence enrichment
- [ ] AWS CloudTrail collector
- [ ] Ollama support (run AI analysis fully offline)
- [ ] Grafana dashboard template
- [ ] Discord + MS Teams alert channels
