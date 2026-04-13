# Sentinel AI — Grafana Dashboard Setup

Get a beautiful security dashboard in 5 minutes.

## Prerequisites

- Grafana 10+ running (or use Grafana Cloud free tier)
- Prometheus running and scraping Sentinel AI

## Step 1 — Enable Prometheus Exporter

In `.env`:
```env
PROMETHEUS_PORT=9090
SENTINEL_SERVER_NAME=prod-server-01   # human-readable name
```

In `sentinel.py`, add to startup:
```python
from monitoring.prometheus_exporter import start_exporter
await start_exporter()
```

Verify: `curl http://localhost:9090/metrics`

## Step 2 — Add to Prometheus

In `prometheus.yml`:
```yaml
scrape_configs:
  - job_name: sentinel-ai
    static_configs:
      - targets:
          - localhost:9090        # server 1
          - 10.0.0.2:9090        # server 2 (multi-server)
          - 10.0.0.3:9090        # server 3
```

## Step 3 — Import Dashboard

1. Open Grafana → **Dashboards → Import**
2. Upload `monitoring/grafana_dashboard.json`
3. Select your Prometheus datasource
4. Click **Import**

You'll instantly see:
- 🚨 Critical / High threat counters
- 📈 Threat rate over time
- 🎯 Threats by type (bar gauge)
- 🌍 Top attacker IPs table
- 🖥️ Multi-server overview (one line per server)

## Step 4 — Set Up Alerting (optional)

In Grafana, create an alert rule:
```
Condition: sentinel_threats_total{risk="CRITICAL"} > 0
Evaluate every: 1m
Notify: your Slack / PagerDuty / email channel
```
