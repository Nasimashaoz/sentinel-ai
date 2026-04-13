"""
Sentinel AI — Prometheus Metrics Exporter
Exposes /metrics endpoint for Prometheus scraping.
Works with the included Grafana dashboard (monitoring/grafana_dashboard.json).

Metrics exposed:
  sentinel_threats_total{risk, type, server}   — counter per threat
  sentinel_threats_by_type_total{type}         — counter by threat type
  sentinel_threats_by_ip_total{source_ip}      — counter by attacker IP
  sentinel_uptime_seconds                      — agent uptime
  sentinel_alerts_sent_total{channel}          — alerts sent per channel
"""

import asyncio
import logging
import os
import socket
import time
from aiohttp import web

log = logging.getLogger(__name__)

# In-memory metric stores (Prometheus text format, no dependencies)
_counters: dict = {}
_start_time = time.time()
SERVER_NAME = os.getenv("SENTINEL_SERVER_NAME", socket.gethostname())


def _inc(metric: str, labels: dict = None, value: float = 1.0):
    label_str = ",".join(f'{k}="{v}"' for k, v in (labels or {}).items())
    key = f"{metric}{{{label_str}}}" if label_str else metric
    _counters[key] = _counters.get(key, 0.0) + value


def record_threat(threat: dict):
    """Call this whenever a threat is detected."""
    risk = threat.get("risk", "UNKNOWN")
    t_type = threat.get("type", "UNKNOWN")
    source_ip = threat.get("source_ip", "unknown")
    _inc("sentinel_threats_total", {"risk": risk, "type": t_type, "server": SERVER_NAME})
    _inc("sentinel_threats_by_type_total", {"type": t_type})
    _inc("sentinel_threats_by_ip_total", {"source_ip": source_ip})


def record_alert_sent(channel: str):
    """Call this after each successful alert send."""
    _inc("sentinel_alerts_sent_total", {"channel": channel, "server": SERVER_NAME})


def _render_metrics() -> str:
    lines = []
    # Uptime gauge
    uptime = time.time() - _start_time
    lines.append("# HELP sentinel_uptime_seconds Sentinel AI agent uptime in seconds")
    lines.append("# TYPE sentinel_uptime_seconds gauge")
    lines.append(f'sentinel_uptime_seconds{{server="{SERVER_NAME}"}} {uptime:.1f}')
    # Counters
    for name in ("sentinel_threats_total", "sentinel_threats_by_type_total",
                 "sentinel_threats_by_ip_total", "sentinel_alerts_sent_total"):
        relevant = {k: v for k, v in _counters.items() if k.startswith(name)}
        if relevant:
            lines.append(f"# TYPE {name} counter")
            for k, v in relevant.items():
                lines.append(f"{k} {v:.0f}")
    return "\n".join(lines) + "\n"


async def metrics_handler(request):
    return web.Response(text=_render_metrics(), content_type="text/plain")


async def start_exporter(port: int = None):
    port = port or int(os.getenv("PROMETHEUS_PORT", 9090))
    app = web.Application()
    app.router.add_get("/metrics", metrics_handler)
    app.router.add_get("/health", lambda r: web.Response(text="ok"))
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    log.info(f"📊 Prometheus exporter running on :{port}/metrics")
    return runner
