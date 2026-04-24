"""
Sentinel AI — Multi-Server Mesh Node

Each server runs a node that:
  1. Runs local threat detection (collector + analyzer)
  2. Pushes incidents to the mesh coordinator via HTTP
  3. Pulls the global threat picture (shared blocklist, cross-server patterns)

Environment variables:
  MESH_COORDINATOR_URL   — URL of the coordinator (e.g. http://10.0.0.1:8888)
  MESH_NODE_SECRET       — shared secret for mesh auth
  SENTINEL_SERVER_NAME   — human-readable name for this node (default: hostname)
"""

import asyncio
import logging
import os
import socket
from datetime import datetime, timezone
import aiohttp

log = logging.getLogger(__name__)

SERVER_NAME = os.getenv("SENTINEL_SERVER_NAME", socket.gethostname())
COORDINATOR_URL = os.getenv("MESH_COORDINATOR_URL", "")
NODE_SECRET = os.getenv("MESH_NODE_SECRET", "change_me")


class MeshNode:
    def __init__(self):
        self.coordinator = COORDINATOR_URL.rstrip("/")
        self.secret = NODE_SECRET
        self.enabled = bool(self.coordinator)
        if self.enabled:
            log.info(f"🌐 Mesh node active: {SERVER_NAME} → {self.coordinator}")

    @property
    def _headers(self):
        return {"X-Sentinel-Secret": self.secret, "X-Sentinel-Node": SERVER_NAME}

    async def push_threat(self, threat: dict):
        """Send a detected threat to the mesh coordinator."""
        if not self.enabled:
            return
        payload = {**threat, "server": SERVER_NAME, "timestamp": threat.get("timestamp", datetime.now(timezone.utc).isoformat())}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{self.coordinator}/api/threats",
                    json=payload, headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        log.debug(f"Mesh: threat pushed from {SERVER_NAME}")
        except Exception as e:
            log.debug(f"Mesh push failed: {e}")

    async def pull_blocklist(self) -> set:
        """Pull the global blocklist from the coordinator."""
        if not self.enabled:
            return set()
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.coordinator}/api/blocklist",
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return set(data.get("ips", []))
        except Exception as e:
            log.debug(f"Mesh blocklist pull failed: {e}")
        return set()

    async def heartbeat(self):
        """Send a periodic heartbeat so the coordinator knows this node is alive."""
        if not self.enabled:
            return
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"{self.coordinator}/api/heartbeat",
                    json={"server": SERVER_NAME, "ts": datetime.now(timezone.utc).isoformat()},
                    headers=self._headers,
                    timeout=aiohttp.ClientTimeout(total=3),
                )
        except Exception:
            pass
