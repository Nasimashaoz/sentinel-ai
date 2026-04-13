"""
Sentinel AI — Threat Intelligence Engine
Enriches source IPs with AbuseIPDB, GreyNoise, and local blocklist data.
"""

import asyncio
import logging
import os
from pathlib import Path
from typing import Optional
import aiohttp

log = logging.getLogger(__name__)

# Local blocklist cache (populated from feeds)
_local_blocklist: set = set()


class ThreatIntel:
    def __init__(self):
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
        self.greynoise_key = os.getenv("GREYNOISE_API_KEY")
        self._cache: dict = {}  # ip -> enrichment result

    async def enrich(self, ip: str) -> dict:
        """Enrich an IP with threat intelligence. Returns a dict with intel data."""
        if not ip or ip in ("localhost", "127.0.0.1"):
            return {}

        # Check cache (TTL: 1 hour in memory)
        if ip in self._cache:
            return self._cache[ip]

        result = {"ip": ip, "sources": []}

        # Run enrichments in parallel
        tasks = []
        if self.abuseipdb_key:
            tasks.append(self._abuseipdb_lookup(ip))
        if self.greynoise_key:
            tasks.append(self._greynoise_lookup(ip))
        tasks.append(self._check_local_blocklist(ip))

        enrichments = await asyncio.gather(*tasks, return_exceptions=True)
        for e in enrichments:
            if isinstance(e, dict):
                result.update(e)

        self._cache[ip] = result
        return result

    async def _abuseipdb_lookup(self, ip: str) -> dict:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, params=params, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = (await resp.json()).get("data", {})
                        abuse_score = data.get("abuseConfidenceScore", 0)
                        reports = data.get("totalReports", 0)
                        country = data.get("countryCode", "")
                        isp = data.get("isp", "")
                        result = {
                            "abuseipdb_score": abuse_score,
                            "abuseipdb_reports": reports,
                            "country": country,
                            "isp": isp,
                            "sources": ["AbuseIPDB"],
                        }
                        if abuse_score >= 80:
                            result["known_malicious"] = True
                            log.warning(f"🚨 IP {ip} has AbuseIPDB score {abuse_score} ({reports} reports)")
                        return result
        except Exception as e:
            log.debug(f"AbuseIPDB lookup failed for {ip}: {e}")
        return {}

    async def _greynoise_lookup(self, ip: str) -> dict:
        url = f"https://api.greynoise.io/v3/community/{ip}"
        headers = {"key": self.greynoise_key}
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return {
                            "greynoise_noise": data.get("noise", False),
                            "greynoise_riot": data.get("riot", False),
                            "greynoise_classification": data.get("classification", ""),
                            "greynoise_name": data.get("name", ""),
                            "sources": ["GreyNoise"],
                        }
        except Exception as e:
            log.debug(f"GreyNoise lookup failed for {ip}: {e}")
        return {}

    async def _check_local_blocklist(self, ip: str) -> dict:
        global _local_blocklist
        if ip in _local_blocklist:
            return {"local_blocklist": True, "sources": ["LocalBlocklist"]}
        return {}

    def add_to_blocklist(self, ip: str):
        _local_blocklist.add(ip)
        log.info(f"Added {ip} to local blocklist")

    def format_for_alert(self, intel: dict) -> str:
        """Format threat intel into a human-readable string for alert messages."""
        if not intel:
            return ""
        parts = []
        if intel.get("known_malicious"):
            parts.append(f"🚨 Known malicious (AbuseIPDB score: {intel.get('abuseipdb_score')}%,"
                         f" {intel.get('abuseipdb_reports')} reports)")
        if intel.get("greynoise_noise"):
            cls = intel.get("greynoise_classification", "unknown")
            name = intel.get("greynoise_name", "")
            parts.append(f"🌐 GreyNoise: {cls} scanner{' (' + name + ')' if name else ''}")
        if intel.get("greynoise_riot"):
            parts.append("✅ GreyNoise RIOT: known benign infrastructure")
        if intel.get("country"):
            parts.append(f"🏳️ Country: {intel.get('country')} | ISP: {intel.get('isp', 'N/A')}")
        if intel.get("local_blocklist"):
            parts.append("⛔ IP is in your local blocklist")
        return "\n".join(parts)
