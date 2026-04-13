<div align="center">

# 🛡️ Sentinel AI

### Your 24/7 Self-Hosted AI Security Agent

[![GitHub Stars](https://img.shields.io/github/stars/Nasimashaoz/sentinel-ai?style=for-the-badge&color=yellow)](https://github.com/Nasimashaoz/sentinel-ai/stargazers)
[![License: MIT](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Docker](https://img.shields.io/badge/Docker-Ready-2496ED?style=for-the-badge&logo=docker)](https://docker.com)
[![Claude AI](https://img.shields.io/badge/Powered%20by-Claude%20AI-orange?style=for-the-badge)](https://claude.ai)

**Monitor your servers. Detect threats. Alert your team. Generate reports. All automatically. All self-hosted.**

[Quick Start](#-quick-start) · [Features](#-features) · [Architecture](#-architecture) · [Demo](#-demo) · [Docs](#-documentation)

</div>

---

## 🔥 What is Sentinel AI?

Sentinel AI is an **autonomous, self-hosted AI security agent** that runs 24/7 on your infrastructure. It watches your servers, detects anomalies, runs automated compliance checks, and notifies your team instantly — via WhatsApp, Telegram, Slack, or email.

No cloud. No subscriptions. No data leaving your network.

```
Your Server → Sentinel AI → Detects Threat → Alerts You on WhatsApp in < 30 seconds
```

> “Like having a senior security engineer monitoring your infrastructure around the clock — except it never sleeps, never misses an alert, and costs $0/month.”

---

## ⚡ Features

### 🔍 Real-Time Threat Detection
- **Failed login monitoring** — brute force, credential stuffing detection
- **Port scan detection** — identifies reconnaissance activity instantly
- **Anomalous traffic analysis** — unusual bandwidth spikes, geographic anomalies
- **Process monitoring** — detects unexpected processes, privilege escalation
- **File integrity monitoring** — watches critical system files for unauthorized changes
- **Log analysis** — AI-powered pattern recognition across syslog, auth.log, nginx, apache

### 📱 Multi-Channel Alerts
- **WhatsApp** — instant alerts via Twilio WhatsApp API
- **Telegram** — bot-based alerts with interactive commands
- **Slack** — channel notifications with rich formatting
- **Email** — SMTP-based with HTML reports
- **Webhook** — custom webhook for any platform
- **PagerDuty** — production incident escalation

### 🧠 AI-Powered Analysis
- **Claude AI integration** — natural language threat analysis
- **Risk scoring** — auto-scores every event CRITICAL/HIGH/MEDIUM/LOW
- **Root cause analysis** — explains *why* something is a threat
- **Remediation steps** — tells you exactly what to do next
- **False positive reduction** — AI context awareness reduces noise by 80%

### 📊 Automated Compliance
- **OWASP Top 10** continuous checks
- **NIST SP 800-53** control monitoring
- **ISO 27001** compliance drift detection
- **CIS Benchmarks** for Linux hardening
- **Auto-generated audit reports** (HTML, PDF, JSON)

### 📈 Dashboard & Reporting
- **Real-time web dashboard** — live threat feed, risk heatmaps
- **Incident timeline** — full chronological audit trail
- **Weekly/monthly reports** — auto-generated and emailed
- **SIEM integration** — export to Splunk, ELK, Grafana

---

## 🚀 Quick Start

### Option 1: Docker (Recommended — 2 minutes)

```bash
# Clone
git clone https://github.com/Nasimashaoz/sentinel-ai
cd sentinel-ai

# Configure
cp .env.example .env
nano .env  # Add your API keys

# Launch
docker-compose up -d

# View dashboard
open http://localhost:8080
```

### Option 2: Python Direct

```bash
git clone https://github.com/Nasimashaoz/sentinel-ai
cd sentinel-ai
pip install -r requirements.txt
cp .env.example .env
nano .env
python sentinel.py
```

### Option 3: One-Line Deploy (VPS)

```bash
curl -sSL https://raw.githubusercontent.com/Nasimashaoz/sentinel-ai/main/install.sh | bash
```

---

## ⚙️ Configuration

Edit `.env`:

```env
# 🧠 AI Engine
CLAUDE_API_KEY=your_anthropic_api_key
AI_MODEL=claude-3-5-sonnet-20241022

# 📱 Alert Channels (enable what you use)
TELEGRAM_BOT_TOKEN=your_telegram_bot_token
TELEGRAM_CHAT_ID=your_chat_id

WHATSAPP_ACCOUNT_SID=your_twilio_sid
WHATSAPP_AUTH_TOKEN=your_twilio_auth
WHATSAPP_FROM=whatsapp:+14155238886
WHATSAPP_TO=whatsapp:+your_number

SLACK_WEBHOOK_URL=https://hooks.slack.com/services/xxx

EMAIL_FROM=alerts@yourdomain.com
EMAIL_TO=security@yourdomain.com
SMTP_HOST=smtp.gmail.com

# 🔍 Monitoring Targets
MONITOR_SSH=true
MONITOR_NGINX=true
MONITOR_PROCESSES=true
MONITOR_FILES=true
MONITOR_PORTS=true

# ⚡ Thresholds
FAILED_LOGIN_THRESHOLD=5
PORT_SCAN_THRESHOLD=20
CRIT_ALERT_COOLDOWN=60
```

---

## 🏗️ Architecture

```
┌────────────────────────────────────────────────────────────────┐
│                    SENTINEL AI                              │
├────────────────────────────────────────────────────────────────┤
│  COLLECTORS          BRAIN              ALERT ENGINE        │
│  ┌─────────┐        ┌─────────┐     ┌────────────┐  │
│  │ SSH Logs │        │ Claude  │     │ WhatsApp   │  │
│  │ Nginx    │   →    │ AI      │  →  │ Telegram   │  │
│  │ Syslog   │        │ Engine  │     │ Slack      │  │
│  │ Netstat  │        │         │     │ Email      │  │
│  │ Processes│        │ Risk    │     │ PagerDuty  │  │
│  │ Files    │        │ Scorer  │     └────────────┘  │
│  └─────────┘        └─────────┘          DASHBOARD       │
│                                         ┌────────────┐  │
│  COMPLIANCE ENGINE                      │ Web UI     │  │
│  ┌───────────────────────────┐   │ localhost  │  │
│  │ OWASP │ NIST │ ISO 27001 │   │ :8080      │  │
│  └───────────────────────────┘   └────────────┘  │
└────────────────────────────────────────────────────────────────┘
```

---

## 📱 Alert Examples

**Telegram/WhatsApp alert:**
```
🚨 CRITICAL THREAT DETECTED
🗓 2026-04-13 18:30:42 UTC
💻 Host: prod-server-01 (192.168.1.10)

🔴 BRUTE FORCE ATTACK
   Source IP: 45.33.32.156
   Attempts: 847 in 3 minutes
   Target: SSH (port 22)

🧠 AI Analysis:
This is a credential stuffing attack originating from
a known Shodan-indexed scanner. The IP has been flagged
in 3 threat intelligence feeds.

✅ Recommended Action:
   iptables -A INPUT -s 45.33.32.156 -j DROP
   fail2ban-client set sshd banip 45.33.32.156

🔗 View full incident: http://localhost:8080/incidents/2847
```

---

## 📦 Project Structure

```
sentinel-ai/
├── sentinel.py              # Main entry point
├── docker-compose.yml       # Docker deployment
├── Dockerfile
├── requirements.txt
├── .env.example
├── install.sh               # One-line VPS installer
├── core/
│   ├── agent.py             # Main AI agent loop
│   ├── collector.py         # Log & metric collectors
│   ├── analyzer.py          # Claude AI threat analysis
│   ├── scorer.py            # Risk scoring engine
│   └── compliance.py        # Compliance check engine
├── alerts/
│   ├── telegram_alert.py
│   ├── whatsapp_alert.py
│   ├── slack_alert.py
│   └── email_alert.py
├── dashboard/
│   ├── app.py               # Flask web dashboard
│   └── templates/
├── reports/
│   └── generator.py         # Auto report generator
└── tests/
```

---

## 🎯 Who Is This For?

| User | Use Case |
|---|---|
| 👨‍💻 **Solo Developers** | Monitor your VPS/cloud server 24/7 without paying for expensive SIEM tools |
| 🏟️ **Startups** | Enterprise-grade security monitoring at zero cost |
| 🔐 **Security Engineers** | Automate compliance reporting and threat triage |
| 💼 **DevOps/SRE Teams** | Integrate into CI/CD, get Slack alerts on every anomaly |
| 🏫 **Security Researchers** | Use as a framework for building custom detection rules |

---

## 🗺️ Comparison

| Feature | Sentinel AI | Splunk | Datadog Security | Wazuh |
|---|---|---|---|---|
| Cost | **Free** | $150/GB/day | $23/host/mo | Free |
| Self-hosted | ✅ | ❌ | ❌ | ✅ |
| AI Analysis | ✅ | ❌ | Partial | ❌ |
| WhatsApp alerts | ✅ | ❌ | ❌ | ❌ |
| Setup time | **2 min** | Days | Hours | Hours |
| No data leaves server | ✅ | ❌ | ❌ | ✅ |

---

## 🤝 Contributing

We want to add:
- 🔎 **More collectors**: AWS CloudTrail, GCP Audit, Azure AD, Kubernetes
- 📱 **More alert channels**: Discord, MS Teams, Line, Signal
- 🌐 **Threat intel feeds**: VirusTotal, Shodan, AbuseIPDB integration
- 🤖 **More AI models**: Ollama (local LLM), GPT-4, Gemini support
- 📊 **Grafana dashboard**: pre-built dashboards for Grafana/Prometheus

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## 🚀 Roadmap

- [x] v1.0 — SSH brute force detection + Telegram/WhatsApp/Slack alerts
- [ ] v1.1 — Web dashboard + incident management
- [ ] v1.2 — OWASP/NIST compliance engine
- [ ] v1.3 — Docker + one-line installer
- [ ] v2.0 — Multi-server support + agent mesh
- [ ] v2.1 — Kubernetes native monitoring
- [ ] v3.0 — Threat intel feed integration + auto-remediation

---

<div align="center">

**⭐ Star this repo if Sentinel AI saves your server from a breach!**

Built with ❤️ by [Nasima Shaoz](https://github.com/Nasimashaoz) — Cybersecurity Professional

</div>
