"""
Sentinel AI — Ollama Offline AI Analyzer
Run AI threat analysis 100% locally using Ollama (no API key, no internet required).
Supports: llama3, mistral, gemma2, phi3, and any Ollama-compatible model.

Install Ollama: https://ollama.ai
Pull a model:   ollama pull llama3
"""

import asyncio
import json
import logging
import os
from typing import Optional
import aiohttp

log = logging.getLogger(__name__)


class OllamaAnalyzer:
    """
    Drop-in replacement for ThreatAnalyzer that runs locally via Ollama.
    Set OLLAMA_ENABLED=true and OLLAMA_MODEL=llama3 in .env to activate.
    """

    def __init__(self):
        self.base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        self.model = os.getenv("OLLAMA_MODEL", "llama3")
        self.enabled = os.getenv("OLLAMA_ENABLED", "false").lower() == "true"
        if self.enabled:
            log.info(f"🧠 Ollama offline analyzer: ENABLED (model: {self.model})")

    async def analyze(self, event: dict) -> Optional[dict]:
        if not self.enabled or not event:
            return None

        risk = self._rule_based_check(event)
        if not risk:
            return None

        threat = {**event, "risk": risk, "ai_analysis": "", "remediation": ""}

        try:
            ai_result = await self._ollama_analyze(event)
            threat["ai_analysis"] = ai_result.get("analysis", "")
            threat["remediation"] = ai_result.get("remediation", "")
            threat["risk"] = ai_result.get("risk", risk)
        except Exception as e:
            log.debug(f"Ollama analysis error: {e}")

        return threat

    def _rule_based_check(self, event: dict) -> Optional[str]:
        rules = {
            "BRUTE_FORCE": "CRITICAL" if event.get("count", 0) >= 50 else "HIGH",
            "PORT_SCAN": "HIGH",
            "WEB_SCAN": "MEDIUM" if event.get("count", 0) < 100 else "HIGH",
            "SUSPICIOUS_PROCESS": "CRITICAL",
        }
        return rules.get(event.get("type", ""))

    async def _ollama_analyze(self, event: dict) -> dict:
        prompt = f"""You are a senior cybersecurity analyst. Analyze this security event.
Event: {json.dumps(event)}

Respond ONLY with this JSON (no extra text):
{{"risk": "CRITICAL|HIGH|MEDIUM|LOW", "analysis": "2 sentence explanation", "remediation": "exact command to run"}}"""

        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "format": "json",
        }

        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=aiohttp.ClientTimeout(total=30),
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    text = data.get("response", "{}")
                    return json.loads(text)
                else:
                    log.error(f"Ollama returned {resp.status}")
                    return {}

    async def health_check(self) -> bool:
        """Check if Ollama is running and the model is available."""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"{self.base_url}/api/tags",
                    timeout=aiohttp.ClientTimeout(total=3),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        models = [m["name"] for m in data.get("models", [])]
                        if any(self.model in m for m in models):
                            log.info(f"✅ Ollama ready: {self.model} found")
                            return True
                        else:
                            log.warning(f"⚠️ Ollama running but model '{self.model}' not found. Run: ollama pull {self.model}")
                            return False
        except Exception:
            log.warning(f"⚠️ Ollama not reachable at {self.base_url}")
            return False
