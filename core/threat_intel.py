"""
Sentinel AI — Live Threat Intelligence Engine
Enriches detected threats with real-time IOC data from:
  - AbuseIPDB    (IP reputation — abuse reports, usage type, ISP)
  - VirusTotal   (IP/domain/hash reputation — 70+ AV engines)
  - Local cache  (24-hour TTL to stay inside free tier limits)

Free tier limits:
  AbuseIPDB:  1,000 checks/day
  VirusTotal: 4 lookups/min, 500/day

Env vars:
  ABUSEIPDB_API_KEY   = your key (https://www.abuseipdb.com/api)
  VIRUSTOTAL_API_KEY  = your key (https://www.virustotal.com/gui/my-apikey)
  THREAT_INTEL_CACHE_HOURS = 24  (how long to cache results)
  THREAT_INTEL_MIN_SCORE   = 20  (AbuseIPDB confidence % to flag as malicious)
"""

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Optional

import aiohttp

log = logging.getLogger(__name__)

CACHE_FILE = Path("data/threat_intel_cache.json")
CACHE_HOURS = int(os.getenv("THREAT_INTEL_CACHE_HOURS", "24"))
MIN_ABUSE_SCORE = int(os.getenv("THREAT_INTEL_MIN_SCORE", "20"))

# IPs that should never be looked up (private / loopback / link-local)
SKIP_PREFIXES = (
    "127.", "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
    "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "169.254.", "::1", "fc", "fd", "fe80",
    "unknown", "0.0.0.0",
)


class ThreatIntelEngine:
    def __init__(self):
        self.abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY", "")
        self.virustotal_key = os.getenv("VIRUSTOTAL_API_KEY", "")
        self._cache: dict = {}
        self._load_cache()
        log.info(
            f"🔍 Threat intel: AbuseIPDB={'✅' if self.abuseipdb_key else '❌ (no key)'} "
            f"VirusTotal={'✅' if self.virustotal_key else '❌ (no key)'}"
        )

    # ─── Cache ────────────────────────────────────────────────────────────────

    def _load_cache(self):
        try:
            if CACHE_FILE.exists():
                self._cache = json.loads(CACHE_FILE.read_text())
        except Exception:
            self._cache = {}

    def _save_cache(self):
        try:
            CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
            CACHE_FILE.write_text(json.dumps(self._cache, indent=2))
        except Exception as e:
            log.debug(f"Cache save error: {e}")

    def _cache_get(self, key: str) -> Optional[dict]:
        entry = self._cache.get(key)
        if entry and time.time() - entry.get("_cached_at", 0) < CACHE_HOURS * 3600:
            return entry
        return None

    def _cache_set(self, key: str, data: dict):
        data["_cached_at"] = time.time()
        self._cache[key] = data
        self._save_cache()

    # ─── Public API ───────────────────────────────────────────────────────────

    async def enrich(self, threat: dict) -> dict:
        """Enrich a threat dict with live IOC data. Returns updated threat."""
        ip = threat.get("source_ip", "")
        if not ip or any(ip.startswith(p) for p in SKIP_PREFIXES):
            return threat

        intel = await self._lookup_ip(ip)
        if not intel:
            return threat

        threat["threat_intel"] = intel

        # Escalate risk if IP is known malicious
        if intel.get("malicious"):
            current = threat.get("risk", "MEDIUM")
            if current in ("LOW", "MEDIUM"):
                threat["risk"] = "HIGH"
                threat["risk_escalated"] = f"Escalated: {intel.get('reason', 'known malicious IP')}"
            elif current == "HIGH":
                threat["risk"] = "CRITICAL"
                threat["risk_escalated"] = f"Escalated to CRITICAL: {intel.get('reason')}"
        return threat

    async def _lookup_ip(self, ip: str) -> Optional[dict]:
        cached = self._cache_get(ip)
        if cached:
            log.debug(f"Threat intel cache hit: {ip}")
            return cached

        results = await asyncio.gather(
            self._abuseipdb_check(ip),
            self._virustotal_check(ip),
            return_exceptions=True,
        )
        abuse = results[0] if not isinstance(results[0], Exception) else {}
        vt = results[1] if not isinstance(results[1], Exception) else {}

        if not abuse and not vt:
            return None

        intel = self._merge_intel(ip, abuse or {}, vt or {})
        self._cache_set(ip, intel)
        return intel

    # ─── AbuseIPDB ────────────────────────────────────────────────────────────

    async def _abuseipdb_check(self, ip: str) -> dict:
        if not self.abuseipdb_key:
            return {}
        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.get(
                    "https://api.abuseipdb.com/api/v2/check",
                    params={"ipAddress": ip, "maxAgeInDays": 30, "verbose": True},
                    headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
                    timeout=aiohttp.ClientTimeout(total=8),
                )
                if resp.status != 200:
                    return {}
                data = (await resp.json()).get("data", {})
                return {
                    "abuse_score": data.get("abuseConfidenceScore", 0),
                    "abuse_reports": data.get("totalReports", 0),
                    "abuse_country": data.get("countryCode", ""),
                    "abuse_isp": data.get("isp", ""),
                    "abuse_usage_type": data.get("usageType", ""),
                    "abuse_domain": data.get("domain", ""),
                    "abuse_last_reported": data.get("lastReportedAt", ""),
                    "abuse_is_tor": data.get("isTor", False),
                    "abuse_is_whitelisted": data.get("isWhitelisted", False),
                }
        except Exception as e:
            log.debug(f"AbuseIPDB error for {ip}: {e}")
            return {}

    # ─── VirusTotal ───────────────────────────────────────────────────────────

    async def _virustotal_check(self, ip: str) -> dict:
        if not self.virustotal_key:
            return {}
        try:
            async with aiohttp.ClientSession() as session:
                resp = await session.get(
                    f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                    headers={"x-apikey": self.virustotal_key},
                    timeout=aiohttp.ClientTimeout(total=8),
                )
                if resp.status != 200:
                    return {}
                data = (await resp.json()).get("data", {}).get("attributes", {})
                stats = data.get("last_analysis_stats", {})
                return {
                    "vt_malicious": stats.get("malicious", 0),
                    "vt_suspicious": stats.get("suspicious", 0),
                    "vt_harmless": stats.get("harmless", 0),
                    "vt_undetected": stats.get("undetected", 0),
                    "vt_country": data.get("country", ""),
                    "vt_asn": data.get("asn", ""),
                    "vt_as_owner": data.get("as_owner", ""),
                    "vt_reputation": data.get("reputation", 0),
                    "vt_network": data.get("network", ""),
                }
        except Exception as e:
            log.debug(f"VirusTotal error for {ip}: {e}")
            return {}

    # ─── Merge & decide ───────────────────────────────────────────────────────

    def _merge_intel(self, ip: str, abuse: dict, vt: dict) -> dict:
        abuse_score = abuse.get("abuse_score", 0)
        vt_malicious = vt.get("vt_malicious", 0)
        vt_suspicious = vt.get("vt_suspicious", 0)
        is_tor = abuse.get("abuse_is_tor", False)

        malicious = (
            abuse_score >= MIN_ABUSE_SCORE
            or vt_malicious >= 3
            or is_tor
        )
        reasons = []
        if abuse_score >= MIN_ABUSE_SCORE:
            reasons.append(f"AbuseIPDB score {abuse_score}% ({abuse.get('abuse_reports', 0)} reports)")
        if vt_malicious >= 3:
            reasons.append(f"VirusTotal {vt_malicious} engines flagged malicious")
        if is_tor:
            reasons.append("Tor exit node")

        intel = {
            "ip": ip,
            "malicious": malicious,
            "reason": "; ".join(reasons) if reasons else "clean",
            "country": abuse.get("abuse_country") or vt.get("vt_country", ""),
            "isp": abuse.get("abuse_isp") or vt.get("vt_as_owner", ""),
            "is_tor": is_tor,
        }
        intel.update(abuse)
        intel.update(vt)
        return intel
