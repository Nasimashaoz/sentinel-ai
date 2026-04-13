"""
Sentinel AI — Mesh Coordinator
Run ONE coordinator on a central server. All other servers are nodes.

Endpoints:
  POST /api/threats       — receive threat from a node
  GET  /api/blocklist     — return global blocklist
  POST /api/heartbeat     — node heartbeat
  GET  /api/nodes         — list all active nodes
  GET  /api/summary       — cross-server threat summary

Run: python -m mesh.coordinator
Or:  uvicorn mesh.coordinator:app
"""

import asyncio
import json
import logging
import os
import time
from collections import defaultdict
from datetime import datetime, timedelta
from aiohttp import web

log = logging.getLogger(__name__)

NODE_SECRET = os.getenv("MESH_NODE_SECRET", "change_me")
COORDINATOR_PORT = int(os.getenv("MESH_COORDINATOR_PORT", 8888))

# In-memory state (swap for Redis in production)
_threats: list = []
_nodes: dict = {}          # server_name -> last_seen timestamp
_global_blocklist: set = set()


def _auth(request: web.Request) -> bool:
    return request.headers.get("X-Sentinel-Secret") == NODE_SECRET


async def post_threat(request: web.Request) -> web.Response:
    if not _auth(request):
        return web.Response(status=401, text="Unauthorized")
    threat = await request.json()
    _threats.append(threat)
    # Auto-blocklist repeat offenders (5+ incidents from same IP)
    ip = threat.get("source_ip", "")
    if ip:
        ip_count = sum(1 for t in _threats if t.get("source_ip") == ip)
        if ip_count >= 5:
            _global_blocklist.add(ip)
            log.info(f"⛔ Auto-blocked {ip} (seen {ip_count} times across mesh)")
    log.info(f"📥 Threat from {threat.get('server')}: {threat.get('type')} [{threat.get('risk')}]")
    return web.json_response({"status": "ok"})


async def get_blocklist(request: web.Request) -> web.Response:
    if not _auth(request):
        return web.Response(status=401, text="Unauthorized")
    return web.json_response({"ips": list(_global_blocklist)})


async def post_heartbeat(request: web.Request) -> web.Response:
    if not _auth(request):
        return web.Response(status=401, text="Unauthorized")
    data = await request.json()
    _nodes[data.get("server", "unknown")] = time.time()
    return web.json_response({"status": "ok"})


async def get_nodes(request: web.Request) -> web.Response:
    if not _auth(request):
        return web.Response(status=401, text="Unauthorized")
    now = time.time()
    nodes = [
        {"server": name, "last_seen": round(now - ts, 1), "online": (now - ts) < 120}
        for name, ts in _nodes.items()
    ]
    return web.json_response({"nodes": nodes, "count": len(nodes)})


async def get_summary(request: web.Request) -> web.Response:
    if not _auth(request):
        return web.Response(status=401, text="Unauthorized")
    cutoff = datetime.utcnow() - timedelta(hours=24)
    recent = [t for t in _threats if _after(t.get("timestamp", ""), cutoff)]
    by_server = defaultdict(int)
    by_type = defaultdict(int)
    by_risk = defaultdict(int)
    for t in recent:
        by_server[t.get("server", "unknown")] += 1
        by_type[t.get("type", "UNKNOWN")] += 1
        by_risk[t.get("risk", "UNKNOWN")] += 1
    return web.json_response({
        "total_24h": len(recent),
        "total_all_time": len(_threats),
        "active_nodes": len(_nodes),
        "by_server": dict(by_server),
        "by_type": dict(by_type),
        "by_risk": dict(by_risk),
        "blocklist_size": len(_global_blocklist),
    })


def _after(ts_str: str, cutoff: datetime) -> bool:
    try:
        return datetime.fromisoformat(ts_str) >= cutoff
    except Exception:
        return False


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/api/threats", post_threat)
    app.router.add_get("/api/blocklist", get_blocklist)
    app.router.add_post("/api/heartbeat", post_heartbeat)
    app.router.add_get("/api/nodes", get_nodes)
    app.router.add_get("/api/summary", get_summary)
    app.router.add_get("/health", lambda r: web.json_response({"status": "ok", "nodes": len(_nodes)}))
    return app


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    log.info(f"🌐 Sentinel AI Mesh Coordinator starting on :{COORDINATOR_PORT}")
    web.run_app(create_app(), port=COORDINATOR_PORT)
