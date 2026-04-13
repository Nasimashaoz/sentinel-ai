<div align="center">

# 🛡️ Sentinel AI

### Your 24/7 Self-Hosted AI Security Agent

[![GitHub Stars](https://img.shields.io/github/stars/Nasimashaoz/sentinel-ai?style=for-the-badge&color=yellow)](https://github.com/Nasimashaoz/sentinel-ai/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)](https://docker.com)
[![Version](https://img.shields.io/badge/version-v1.1.0-01696F?style=for-the-badge)](https://github.com/Nasimashaoz/sentinel-ai/releases)

**Monitor your servers. Detect threats. Alert your team. Generate reports. All automatically. All self-hosted.**

[Quick Start](#-quick-start) · [Features](#-features) · [Alert Channels](#-alert-channels) · [Architecture](#-architecture) · [Docs](#-documentation)

</div>

---

## 🔥 What is Sentinel AI?

Sentinel AI is an **autonomous, self-hosted AI security agent** that runs 24/7 on your infrastructure. It watches your servers, detects anomalies, runs automated compliance checks, and notifies your team instantly — via WhatsApp, Telegram, Slack, Discord, MS Teams, or email.

No cloud. No subscriptions. No data leaving your network.

```
Your Server → Sentinel AI → Detects Threat → Alerts You on WhatsApp in < 30 seconds
```

> “Like having a senior security engineer monitoring your infrastructure around the clock — except it never sleeps, never misses an alert, and costs $0/month.”

---

## ⚡ Features

### 🔍 Real-Time Threat Detection
- **SSH brute force** — detects credential stuffing and dictionary attacks
- **Port scan detection** — identifies reconnaissance activity instantly
- **Process monitoring** — flags unexpected processes and privilege escalation
- **File integrity monitoring** — SHA-256 hashing of `/etc/passwd`, `/etc/shadow`, SSH config, sudoers, crontab
- **Web attack detection** — SQLi, XSS, path traversal from nginx/apache logs
- **Log analysis** — AI pattern recognition across syslog, auth.log, nginx, apache

### 📱 Alert Channels (6 supported)

| Channel | Setup Guide |
|---|---|
| 📬 **WhatsApp** | [SETUP_WHATSAPP.md](docs/SETUP_WHATSAPP.md) |
| 🤖 **Telegram** (+ interactive bot) | [SETUP_TELEGRAM.md](docs/SETUP_TELEGRAM.md) |
| 💬 **Slack** | [SETUP_SLACK.md](docs/SETUP_SLACK.md) |
| 💙 **Discord** (rich embeds) | [SETUP_DISCORD.md](docs/SETUP_DISCORD.md) |
| 🏢 **Microsoft Teams** (Adaptive Cards) | included |
| 📧 **Email** (HTML reports) | included |

### 🧠 AI Analysis — Cloud or Offline

| Mode | Engine | Cost | Internet |
|---|---|---|---|
| **Cloud** | Claude 3.5 Sonnet | ~$0.01/alert | Required |
| **Offline** | Ollama (llama3, mistral, gemma2, phi3) | **Free** | **None** |

- Risk scoring: CRITICAL / HIGH / MEDIUM / LOW
- Natural language threat explanation
- Exact remediation command per incident
- 80% false positive reduction vs rule-only engines

### 🔍 Threat Intelligence Enrichment
- **AbuseIPDB** — abuse score, report count, country, ISP (free: 1,000/day)
- **GreyNoise** — noise/riot classification, scanner identification (free tier)
- **Local blocklist** — manageable via Telegram bot commands
- **Auto-blocklist** — IPs attacking 5+ servers across the mesh are auto-blocked

### 📊 Monitoring & Dashboards
- **Live web dashboard** — real-time threat feed, SSE streaming
- **Prometheus exporter** — `/metrics` endpoint, all metrics labeled by server
- **Grafana dashboard** — import-ready JSON (`monitoring/grafana_dashboard.json`)
- **Audit reports** — HTML + JSON, auto-generated on demand

### 🌐 Multi-Server Mesh
- One coordinator, unlimited nodes
- Cross-server threat sync and shared blocklist
- Auto-block IPs seen attacking multiple servers
- Node heartbeat + online/offline status
- Unified `/api/summary` across all servers

### 🛡️ Automated Compliance
- OWASP Top 10 continuous checks
- NIST SP 800-53 control monitoring
- ISO 27001 drift detection
- CIS Benchmarks for Linux hardening

---

## 🚀 Quick Start

### Option 1: Docker (2 minutes)

```bash
git clone https://github.com/Nasimashaoz/sentinel-ai
cd sentinel-ai
cp .env.example .env
nano .env          # add your keys
docker-compose up -d
open http://localhost:8080
```

### Option 2: Python

```bash
git clone https://github.com/Nasimashaoz/sentinel-ai
cd sentinel-ai && pip install -r requirements.txt
cp .env.example .env && nano .env
python sentinel.py
```

### Option 3: One-Line VPS Deploy

```bash
curl -sSL https://raw.githubusercontent.com/Nasimashaoz/sentinel-ai/main/install.sh | bash
```

### Offline Mode (Ollama — no API key)

```bash
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull llama3
# In .env: OLLAMA_ENABLED=true  OLLAMA_MODEL=llama3
python sentinel.py
```

---

## ⚙️ Configuration

```env
# 🧠 AI — pick ONE
CLAUDE_API_KEY=your_anthropic_key          # Cloud
OLLAMA_ENABLED=true                        # OR: offline
OLLAMA_MODEL=llama3

# 📱 Alert channels (add any/all)
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
WHATSAPP_ACCOUNT_SID=...

# 🔍 Threat intelligence (optional, free)
ABUSEIPDB_API_KEY=...
GREYNOISE_API_KEY=...

# 🌐 Multi-server mesh (optional)
MESH_COORDINATOR_URL=http://10.0.0.1:8888
MESH_NODE_SECRET=your_secret
SENTINEL_SERVER_NAME=web-server-01

# 📊 Monitoring
PROMETHEUS_PORT=9090
```

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                     SENTINEL AI                            │
├─────────────┬───────────────┬─────────────────────────┤
│  COLLECTORS   │  AI BRAIN      │  OUTPUT                 │
│               │               │                         │
│  SSH Logs     │  Claude AI     │  📬 WhatsApp            │
│  Nginx/Apache │   or Ollama   │  🤖 Telegram + bot     │
│  Syslog       │               │  💬 Slack               │
│  Netstat      │  Risk Scorer   │  💙 Discord             │
│  Processes    │               │  🏢 MS Teams           │
│  File hashes  │  Threat Intel  │  📊 Grafana/Prometheus  │
│  Compliance   │  AbuseIPDB +   │  🌐 Mesh coordinator   │
│               │  GreyNoise     │                         │
└─────────────┴───────────────┴─────────────────────────┘
```

---

## 📱 Alert Example

```
🚨 CRITICAL: BRUTE FORCE ATTACK
🖥️  Host:      prod-server-01
🌐  Source IP: 45.33.32.156
📊  Count:     847 attempts / 3 min
⚙️  Service:   SSH (port 22)

🚨 Known malicious (AbuseIPDB: 97%, 2,847 reports)
🌐 GreyNoise: malicious scanner (Mirai)
🏳️ Country: CN | ISP: Alibaba Cloud

🧠 AI Analysis:
High-volume credential stuffing from a known Shodan
scanner. Pattern matches Mirai botnet SSH sweep.

✅ Remediation:
iptables -A INPUT -s 45.33.32.156 -j DROP
fail2ban-client set sshd banip 45.33.32.156
```

---

## 🗂️ Project Structure

```
sentinel-ai/
├── sentinel.py              # Main entry point
├── core/
│   ├── agent.py             # Main AI agent loop
│   ├── collector.py         # Log & metric collectors
│   ├── analyzer.py          # Claude AI analysis
│   ├── ollama_analyzer.py   # Offline AI (Ollama)
│   ├── scorer.py            # Risk scoring engine
│   ├── compliance.py        # OWASP/NIST/ISO checks
│   ├── threat_intel.py      # AbuseIPDB + GreyNoise
│   ├── telegram_bot.py      # Interactive bot commands
│   └── file_monitor.py      # File integrity monitor
├── alerts/
│   ├── telegram_alert.py
│   ├── whatsapp_alert.py
│   ├── slack_alert.py
│   ├── discord_alert.py     # ← v1.1
│   └── msteams_alert.py     # ← v1.1
├── mesh/
│   ├── coordinator.py       # Central mesh server
│   └── agent_node.py        # Per-server node
├── monitoring/
│   ├── prometheus_exporter.py
│   └── grafana_dashboard.json
├── dashboard/app.py         # Live web UI
├── reports/generator.py     # HTML/JSON reports
├── tests/                   # 9 test cases
├── docs/                    # 9 setup guides
├── Dockerfile
├── docker-compose.yml
└── install.sh
```

---

## 🎯 Who Is This For?

| User | Use Case |
|---|---|
| 👨‍💻 **Solo Developers** | Monitor your VPS 24/7 without paying for Splunk |
| 🏙️ **Startups** | Enterprise-grade security at zero cost |
| 🔐 **Security Engineers** | Automate compliance reporting and threat triage |
| 💼 **DevOps / SRE** | Integrate into CI/CD, Slack alerts on every anomaly |
| 🌐 **Multi-server teams** | Mesh mode: monitor 10+ servers from one dashboard |

---

## 🗂️ Comparison

| Feature | Sentinel AI | Splunk | Datadog Security | Wazuh |
|---|---|---|---|---|
| Cost | **Free** | $150/GB/day | $23/host/mo | Free |
| Self-hosted | ✅ | ❌ | ❌ | ✅ |
| AI analysis | ✅ Cloud + Offline | ❌ | Partial | ❌ |
| WhatsApp / Discord | ✅ | ❌ | ❌ | ❌ |
| Threat intel (AbuseIPDB) | ✅ | Paid add-on | Paid | ❌ |
| Grafana dashboard | ✅ | Separate | Separate | ✅ |
| Multi-server mesh | ✅ | ✅ | ✅ | ✅ |
| Setup time | **2 min** | Days | Hours | Hours |
| Data leaves server | **Never** | Yes | Yes | No |

---

## 📚 Documentation

| Guide | Link |
|---|---|
| Telegram setup | [docs/SETUP_TELEGRAM.md](docs/SETUP_TELEGRAM.md) |
| WhatsApp setup | [docs/SETUP_WHATSAPP.md](docs/SETUP_WHATSAPP.md) |
| Slack setup | [docs/SETUP_SLACK.md](docs/SETUP_SLACK.md) |
| Discord setup | [docs/SETUP_DISCORD.md](docs/SETUP_DISCORD.md) |
| Telegram bot commands | [docs/TELEGRAM_BOT_COMMANDS.md](docs/TELEGRAM_BOT_COMMANDS.md) |
| Ollama offline AI | [docs/SETUP_OLLAMA.md](docs/SETUP_OLLAMA.md) |
| Threat intelligence | [docs/SETUP_THREAT_INTEL.md](docs/SETUP_THREAT_INTEL.md) |
| Grafana dashboard | [docs/GRAFANA_SETUP.md](docs/GRAFANA_SETUP.md) |
| Multi-server mesh | [docs/MULTI_SERVER.md](docs/MULTI_SERVER.md) |
| VPS deployment | [docs/VPS_DEPLOY.md](docs/VPS_DEPLOY.md) |
| Architecture deep-dive | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| FAQ | [docs/FAQ.md](docs/FAQ.md) |

---

## 🗟a️ Roadmap

- [x] **v1.0** — SSH detection, Telegram/WhatsApp/Slack/Email alerts, Claude AI, compliance engine, web dashboard, Docker
- [x] **v1.1** — Discord, MS Teams, Ollama offline AI, AbuseIPDB/GreyNoise, Telegram bot commands, File Integrity Monitor, Prometheus/Grafana, Multi-server mesh
- [ ] **v1.2** — Kubernetes native monitoring, Helm chart
- [ ] **v1.3** — AWS CloudTrail + GCP Audit Log collectors
- [ ] **v2.0** — Auto-remediation engine (auto-ban, auto-firewall rules)
- [ ] **v2.1** — AI model fine-tuning on your own incident history
- [ ] **v3.0** — SaaS hosted option (for teams who don’t want to self-host)

---

## 🤝 Contributing

PRs welcome! Priority areas:
- New collectors (Kubernetes, AWS, Azure)
- New alert channels (Line, Signal, PagerDuty)
- Detection rules for new attack patterns
- Translations (README in other languages)

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

<div align="center">

**⭐ Star this repo if Sentinel AI saves your server from a breach!**

Built with ❤️ by [Nasima Shaoz](https://github.com/Nasimashaoz) — Cybersecurity Professional, Bengaluru

[![GitHub followers](https://img.shields.io/github/followers/Nasimashaoz?style=social)](https://github.com/Nasimashaoz)

</div>
