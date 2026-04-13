<div align="center">

# 🛡️ Sentinel AI

### Your 24/7 Self-Hosted AI Security Agent

[![GitHub Stars](https://img.shields.io/github/stars/Nasimashaoz/sentinel-ai?style=for-the-badge&color=yellow)](https://github.com/Nasimashaoz/sentinel-ai/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)](https://docker.com)
[![Helm](https://img.shields.io/badge/Helm-Chart-0F1689?style=for-the-badge&logo=helm)](helm/sentinel-ai)
[![CI](https://img.shields.io/github/actions/workflow/status/Nasimashaoz/sentinel-ai/ci.yml?style=for-the-badge&label=CI)](https://github.com/Nasimashaoz/sentinel-ai/actions)
[![Version](https://img.shields.io/badge/version-v1.2.0-01696F?style=for-the-badge)](https://github.com/Nasimashaoz/sentinel-ai/releases)

**Monitor your servers. Detect threats. Alert your team. Respond automatically.**  
**Linux · Kubernetes · AWS · GCP · Azure — all in one agent. Fully self-hosted.**

[Quick Start](#-quick-start) · [Features](#-features) · [Alert Channels](#-alert-channels) · [Cloud Coverage](#-cloud-coverage) · [Docs](#-documentation)

</div>

---

## 🔥 What is Sentinel AI?

Sentinel AI is an **autonomous, self-hosted AI security agent** that runs 24/7 across your entire infrastructure. It watches Linux servers, Kubernetes clusters, AWS, GCP, and Azure — detects threats in real time, enriches them with live threat intelligence, and alerts your team instantly via Telegram, Slack, Discord, WhatsApp, PagerDuty, Signal, or email.

No cloud SaaS. No subscriptions. No data leaving your network.

```
Your Infrastructure → Sentinel AI → Detects Threat → Enriches with AbuseIPDB+VirusTotal
        → AI Analysis → Alerts You in < 30 seconds → (Optional) Auto-Remediates
```

> *"Like having a senior security engineer monitoring your entire cloud infrastructure around the clock — except it never sleeps, never misses an alert, and costs $0/month."*

---

## ⚡ Features

### 🔍 Real-Time Threat Detection

- **SSH brute force** — credential stuffing, dictionary attacks, distributed campaigns
- **Port scan detection** — reconnaissance and network sweep identification
- **Process monitoring** — unexpected processes, privilege escalation, crypto miners
- **File integrity monitoring** — SHA-256 hashing of `/etc/passwd`, SSH config, sudoers, crontab
- **Web attack detection** — SQLi, XSS, path traversal from nginx/apache logs
- **Log analysis** — AI pattern recognition across syslog, auth.log, nginx, apache

### ☁️ Cloud Coverage — All 5 Platforms

| Platform | Collector | What Gets Detected |
|---|---|---|
| 🐧 **Linux** | Built-in | SSH brute force, port scans, processes, file changes, web attacks |
| ☸️ **Kubernetes** | `kubernetes_collector.py` | OOMKilled, crash loops, image pull failures, RBAC Forbidden, privileged pods |
| ☁️ **AWS** | `aws_collector.py` | Root login, CloudTrail disabled, IAM key creation, privilege escalation, S3 ACL changes |
| 🌐 **GCP** | `gcp_collector.py` | IAM policy changes, firewall rules, Storage ACL, audit log deleted, unexpected VMs |
| 🔷 **Azure** | `azure_collector.py` | AD sign-in failures, role assignments, Key Vault access, NSG modifications, diagnostic settings deleted |

### 📱 Alert Channels — 8 Supported

| Channel | What You Get | Setup |
|---|---|---|
| 🤖 **Telegram** | Rich alerts + interactive bot commands | [SETUP_TELEGRAM.md](docs/SETUP_TELEGRAM.md) |
| 📬 **WhatsApp** | Instant mobile alerts via Twilio | [SETUP_WHATSAPP.md](docs/SETUP_WHATSAPP.md) |
| 💬 **Slack** | Channel alerts with AI analysis | [SETUP_SLACK.md](docs/SETUP_SLACK.md) |
| 💙 **Discord** | Rich embeds with colour-coded severity | [SETUP_DISCORD.md](docs/SETUP_DISCORD.md) |
| 🚨 **PagerDuty** | On-call escalation with dedup + auto-resolve | included |
| 📡 **Signal** | Encrypted private alerts via signal-cli | included |
| 🏢 **MS Teams** | Adaptive Cards for enterprise teams | included |
| 📧 **Email** | HTML threat reports, SMTP | included |

### 🧠 AI Analysis — Cloud or Fully Offline

| Mode | Engine | Cost | Internet Required |
|---|---|---|---|
| **Cloud** | Claude 3.5 Sonnet | ~$0.01/alert | Yes |
| **Offline** | Ollama (llama3, mistral, gemma2, phi3) | **Free** | **Never** |

- Risk scoring: CRITICAL / HIGH / MEDIUM / LOW
- Natural language threat explanation
- Exact remediation command per incident
- 80% false positive reduction vs rule-only engines

### 🔍 Live Threat Intelligence

Every detected threat is automatically enriched **before** the alert is sent:

| Source | Data | Free Tier |
|---|---|---|
| **AbuseIPDB** | Abuse confidence %, report count, ISP, Tor exit node | 1,000/day |
| **VirusTotal** | 70+ AV engine detections, reputation score, ASN | 500/day |

- 24-hour local cache — stays within free API limits
- **Auto risk escalation** — LOW→HIGH or HIGH→CRITICAL if IP is known malicious
- Tor exit node auto-detection
- Private IP ranges never consume API quota

### 🛡️ Auto-Remediation (Safe Mode)

- **Dry-run by default** — logs what WOULD run, zero risk
- Whitelist-only execution — only pre-approved commands ever run
- `fail2ban` + `iptables` = safe ✅ · `kill -9` = manual only ❌
- Separate gate for CRITICAL threats (`AUTO_REMEDIATE_CRITICAL=true`)
- Full audit log with rollback command stored per action

### 📊 Monitoring & Dashboards

- **Live web dashboard** — real-time threat feed, SSE streaming
- **Prometheus exporter** — `/metrics` endpoint, all metrics labeled by server
- **Grafana dashboard** — import-ready JSON
- **Audit reports** — HTML + JSON, auto-generated on demand

### 🌐 Multi-Server Mesh

- One coordinator, unlimited nodes
- Cross-server threat sync and shared blocklist
- Auto-block IPs attacking multiple servers
- Node heartbeat + online/offline status

### 🛠️ Automated Compliance

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
nano .env          # add your API keys
docker compose up -d
open http://localhost:8080
```

### Option 2: Kubernetes via Helm (60 seconds)

```bash
git clone https://github.com/Nasimashaoz/sentinel-ai
helm install sentinel-ai ./helm/sentinel-ai \
  --namespace monitoring --create-namespace \
  --set ai.claude.apiKey=$CLAUDE_API_KEY \
  --set alerts.telegram.enabled=true \
  --set alerts.telegram.botToken=$BOT_TOKEN \
  --set alerts.telegram.chatId=$CHAT_ID
```

### Option 3: Python

```bash
git clone https://github.com/Nasimashaoz/sentinel-ai
cd sentinel-ai && pip install -r requirements.txt
cp .env.example .env && nano .env
python sentinel.py
```

### Option 4: One-Line VPS Deploy

```bash
curl -sSL https://raw.githubusercontent.com/Nasimashaoz/sentinel-ai/main/install.sh | bash
```

### Offline Mode (Ollama — no API key needed)

```bash
docker compose --profile ollama up -d
# In .env: OLLAMA_ENABLED=true  OLLAMA_MODEL=llama3
```

---

## ⚙️ Configuration

```env
# AI — pick one
CLAUDE_API_KEY=your_anthropic_key
# OR offline:
OLLAMA_ENABLED=true
OLLAMA_MODEL=llama3

# Alert channels
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHAT_ID=...
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
PAGERDUTY_ROUTING_KEY=...       # on-call escalation
SIGNAL_SENDER=+1234567890       # Signal messenger
SIGNAL_RECIPIENTS=+0987654321

# Threat intelligence (free sign-up, no credit card)
ABUSEIPDB_API_KEY=...           # abuseipdb.com/api
VIRUSTOTAL_API_KEY=...          # virustotal.com

# Cloud collectors
K8S_ENABLED=true
AWS_ENABLED=true   AWS_REGION=us-east-1
GCP_ENABLED=true   GCP_PROJECT_ID=your-project
AZURE_ENABLED=true AZURE_SUBSCRIPTION_ID=...

# Auto-remediation (disabled by default)
AUTO_REMEDIATE=false
AUTO_REMEDIATE_CRITICAL=false
```

Full reference: [`.env.example`](.env.example)

---

## 📱 Alert Example

```
🚨 CRITICAL: SSH BRUTE FORCE
🖥️  Host:      prod-server-01
🌐  Source IP: 45.33.32.156
📊  Count:     847 attempts / 3 min
⚙️  Service:   SSH (port 22)

🔍 Threat Intel:
   AbuseIPDB: 97% confidence · 2,847 reports
   VirusTotal: 8/93 engines flagged malicious
   ISP: Linode LLC · Country: US · Tor: No
   ⬆️ Risk escalated: MEDIUM → CRITICAL

🧠 AI Analysis:
   High-volume credential stuffing from a known
   scanner. Pattern matches automated SSH sweep.

✅ Remediation:
   fail2ban-client set sshd banip 45.33.32.156
   iptables -A INPUT -s 45.33.32.156 -j DROP
```

---

## 🏗️ Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        SENTINEL AI v1.2                          │
├──────────────────┬───────────────────┬───────────────────────────┤
│   COLLECTORS     │   AI BRAIN        │   OUTPUT                  │
│                  │                   │                           │
│  Linux (built-in)│  Claude 3.5       │  🤖 Telegram + bot        │
│  Kubernetes      │   or Ollama       │  📬 WhatsApp              │
│  AWS CloudTrail  │                   │  💬 Slack                 │
│  GCP Audit Logs  │  Risk Scorer      │  💙 Discord               │
│  Azure Activity  │                   │  🚨 PagerDuty             │
│  File Integrity  │  Threat Intel     │  📡 Signal                │
│  Web Logs        │  AbuseIPDB +      │  🏢 MS Teams              │
│  Compliance      │  VirusTotal       │  📊 Grafana/Prometheus    │
│                  │                   │  🌐 Mesh coordinator      │
│                  │  Auto-Remediation │  🛠️ Auto-remediation      │
└──────────────────┴───────────────────┴───────────────────────────┘
```

---

## 🗂️ Project Structure

```
sentinel-ai/
├── sentinel.py                   # Entry point
├── core/
│   ├── agent.py                  # Main AI agent loop
│   ├── analyzer.py               # Claude AI analysis
│   ├── ollama_analyzer.py        # Offline AI (Ollama)
│   ├── scorer.py                 # Risk scoring engine
│   ├── compliance.py             # OWASP/NIST/ISO checks
│   ├── threat_intel.py           # AbuseIPDB + VirusTotal ← v1.2
│   ├── remediation.py            # Auto-remediation engine ← v1.2
│   ├── telegram_bot.py           # Interactive bot commands
│   ├── file_monitor.py           # File integrity monitor
│   └── collectors/
│       ├── linux_collector.py    # SSH, ports, processes, logs
│       ├── kubernetes_collector.py  ← v1.2
│       ├── aws_collector.py         ← v1.2
│       ├── gcp_collector.py         ← v1.2
│       └── azure_collector.py       ← v1.2
├── alerts/
│   ├── telegram_alert.py
│   ├── whatsapp_alert.py
│   ├── slack_alert.py
│   ├── discord_alert.py
│   ├── msteams_alert.py
│   ├── email_alert.py
│   ├── pagerduty_alert.py        ← v1.2
│   └── signal_alert.py           ← v1.2
├── helm/sentinel-ai/             ← v1.2  (Kubernetes Helm chart)
├── mesh/                         # Multi-server coordinator + nodes
├── monitoring/                   # Prometheus + Grafana
├── dashboard/                    # Live web UI
├── reports/                      # HTML/JSON report generator
├── tests/                        # Full test suite (pytest)
├── docs/                         # 19 setup guides
├── .github/workflows/            ← v1.2  (CI + Docker + Release)
├── Dockerfile                    ← v1.2
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
| 💼 **DevOps / SRE** | Kubernetes-native, Helm deploy, Prometheus metrics |
| 🌐 **Multi-cloud teams** | AWS + GCP + Azure unified in one agent |

---

## 🗂️ Comparison

| Feature | Sentinel AI | Splunk | Datadog Security | Wazuh |
|---|---|---|---|---|
| Cost | **Free** | $150/GB/day | $23/host/mo | Free |
| Self-hosted | ✅ | ❌ | ❌ | ✅ |
| AI analysis | ✅ Cloud + Offline | ❌ | Partial | ❌ |
| Kubernetes native | ✅ | Paid add-on | Paid | Partial |
| AWS + GCP + Azure | ✅ | ✅ | ✅ | ❌ |
| PagerDuty + Signal | ✅ | Paid | Paid | ❌ |
| Threat intel (AbuseIPDB+VT) | ✅ | Paid add-on | Paid | ❌ |
| Auto-remediation | ✅ Safe mode | ❌ | ❌ | Partial |
| Helm chart | ✅ | ❌ | ❌ | ✅ |
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
| Threat intelligence | [docs/THREAT_INTEL.md](docs/THREAT_INTEL.md) |
| Kubernetes monitoring | [docs/SETUP_KUBERNETES.md](docs/SETUP_KUBERNETES.md) |
| AWS CloudTrail | [docs/SETUP_AWS.md](docs/SETUP_AWS.md) |
| GCP Audit Logs | [docs/SETUP_GCP.md](docs/SETUP_GCP.md) |
| Azure Activity Logs | [docs/SETUP_AZURE.md](docs/SETUP_AZURE.md) |
| Auto-remediation | [docs/AUTO_REMEDIATION.md](docs/AUTO_REMEDIATION.md) |
| Helm deploy | [docs/HELM_DEPLOY.md](docs/HELM_DEPLOY.md) |
| Grafana dashboard | [docs/GRAFANA_SETUP.md](docs/GRAFANA_SETUP.md) |
| Multi-server mesh | [docs/MULTI_SERVER.md](docs/MULTI_SERVER.md) |
| VPS deployment | [docs/DEPLOY_VPS.md](docs/DEPLOY_VPS.md) |
| Architecture deep-dive | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| FAQ | [docs/FAQ.md](docs/FAQ.md) |

---

## 🗺️ Roadmap

- [x] **v1.0** — SSH detection, Telegram/WhatsApp/Slack/Email, Claude AI, compliance engine, web dashboard, Docker
- [x] **v1.1** — Discord, MS Teams, Ollama offline AI, AbuseIPDB, Telegram bot commands, File Integrity Monitor, Prometheus/Grafana, Multi-server mesh
- [x] **v1.2** — Kubernetes collector, Helm chart, AWS/GCP/Azure collectors, PagerDuty, Signal, VirusTotal threat intel, auto-remediation engine, GitHub Actions CI/CD, full test suite
- [ ] **v2.0** — AI model fine-tuning on your own incident history
- [ ] **v2.1** — SOC2 / PCI-DSS compliance modules
- [ ] **v3.0** — SaaS hosted option (for teams who don't want to self-host)

---

## 🤝 Contributing

PRs welcome! Priority areas:
- New detection rules for emerging attack patterns
- New alert channels
- Translations (README in other languages)
- More cloud collectors (Oracle Cloud, DigitalOcean)

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

<div align="center">

**⭐ Star this repo if Sentinel AI saves your server from a breach!**

Built with ❤️ by [Nasima Shaoz](https://github.com/Nasimashaoz) — Cybersecurity Professional, Bengaluru

[![GitHub followers](https://img.shields.io/github/followers/Nasimashaoz?style=social)](https://github.com/Nasimashaoz)
[![Docker Pulls](https://img.shields.io/badge/docker-ghcr.io%2Fnasimashaoz%2Fsentinel--ai-2496ED?logo=docker)](https://github.com/Nasimashaoz/sentinel-ai/pkgs/container/sentinel-ai)

</div>
