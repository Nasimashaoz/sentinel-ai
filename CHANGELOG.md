# Changelog

All notable changes to Sentinel AI are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [v1.1.0] — 2026-04-13

### Added
- **Discord alerts** — rich color-coded embeds via webhook (`alerts/discord_alert.py`)
- **Microsoft Teams alerts** — Adaptive Cards via incoming webhook (`alerts/msteams_alert.py`)
- **Ollama offline AI** — run llama3/mistral/gemma2/phi3 locally, zero API cost (`core/ollama_analyzer.py`)
- **AbuseIPDB enrichment** — abuse score, report count, country, ISP per attacker IP
- **GreyNoise enrichment** — noise/riot/scanner classification per IP
- **Local blocklist** — persistent, manageable via Telegram bot
- **Interactive Telegram bot** — `/status` `/report` `/top` `/banip` `/unbanip` `/help` (`core/telegram_bot.py`)
- **File Integrity Monitor** — SHA-256 hashing of `/etc/passwd`, `/etc/shadow`, SSH config, sudoers, crontab (`core/file_monitor.py`)
- **Prometheus metrics exporter** — `/metrics` endpoint, all metrics labeled by server (`monitoring/prometheus_exporter.py`)
- **Grafana dashboard** — import-ready JSON with KPI tiles, threat timeline, top IPs, multi-server view (`monitoring/grafana_dashboard.json`)
- **Multi-server mesh coordinator** — centralized threat aggregation, auto-blocklist (`mesh/coordinator.py`)
- **Multi-server mesh node** — threat push, blocklist pull, heartbeat (`mesh/agent_node.py`)
- **Auto-blocklist** — IPs attacking 5+ servers across the mesh are auto-blocked globally
- **Docs**: SETUP_DISCORD.md, SETUP_OLLAMA.md, SETUP_THREAT_INTEL.md, TELEGRAM_BOT_COMMANDS.md, GRAFANA_SETUP.md, MULTI_SERVER.md

### Changed
- README rebuilt for v1.1 — accurate feature list, all 6 channels, updated comparison table, full docs index
- Profile README updated with animated banner and sentinel-ai pin card

---

## [v1.0.0] — 2026-04-13

### Added
- **Core agent loop** — async event-driven architecture (`core/agent.py`)
- **Log collectors** — SSH auth.log, nginx, syslog, netstat, process monitor (`core/collector.py`)
- **Claude AI analyzer** — natural language threat analysis + remediation (`core/analyzer.py`)
- **Risk scorer** — CRITICAL/HIGH/MEDIUM/LOW with weighted rules (`core/scorer.py`)
- **Compliance engine** — OWASP Top 10, NIST SP 800-53, ISO 27001, CIS Benchmarks (`core/compliance.py`)
- **Telegram alert** — bot-based instant notifications (`alerts/telegram_alert.py`)
- **WhatsApp alert** — Twilio WhatsApp API (`alerts/whatsapp_alert.py`)
- **Slack alert** — incoming webhook with rich formatting (`alerts/slack_alert.py`)
- **Email alert** — SMTP HTML reports (`alerts/email_alert.py`)
- **Live web dashboard** — SSE streaming, real-time threat feed (`dashboard/app.py`)
- **Report generator** — HTML + JSON audit reports (`reports/generator.py`)
- **Docker support** — Dockerfile + docker-compose.yml
- **One-line installer** — install.sh for VPS deployment
- **GitHub Actions CI** — automated test pipeline (`.github/workflows/ci.yml`)
- **Test suite** — 9 test cases covering scorer, compliance, report generator
- **Docs**: SETUP_TELEGRAM.md, SETUP_WHATSAPP.md, SETUP_SLACK.md, VPS_DEPLOY.md, ARCHITECTURE.md, FAQ.md

---

## [Unreleased — v1.2.0]

### Planned
- Kubernetes native monitoring (pod crashes, RBAC violations, image pull failures)
- AWS CloudTrail collector (IAM events, S3 access, unusual API calls)
- GCP Audit Log collector
- Azure AD sign-in anomaly detection
- Helm chart for k8s deployment
