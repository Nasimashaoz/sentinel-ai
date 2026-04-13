"""
Sentinel AI — Claude AI Threat Analyzer
Sends events to Claude for intelligent threat analysis and remediation advice.
"""

import logging
import os
from typing import Optional

log = logging.getLogger(__name__)


class ThreatAnalyzer:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self.client = None
        if api_key:
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=api_key)
                log.info("🧠 Claude AI analyzer: ENABLED")
            except ImportError:
                log.warning("anthropic package not installed. Run: pip install anthropic")
        else:
            log.warning("🧠 Claude AI analyzer: DISABLED (no API key). Rule-based analysis only.")

    async def analyze(self, event: dict) -> Optional[dict]:
        """Analyze a security event. Returns enriched threat dict or None if benign."""
        if not event:
            return None

        # Rule-based pre-filter (fast, no API call)
        risk = self._rule_based_check(event)
        if not risk:
            return None

        threat = {**event, "risk": risk, "ai_analysis": "", "remediation": ""}

        # AI enrichment (if Claude API key available)
        if self.client:
            try:
                ai_result = await self._claude_analyze(event)
                threat["ai_analysis"] = ai_result.get("analysis", "")
                threat["remediation"] = ai_result.get("remediation", "")
                threat["risk"] = ai_result.get("risk", risk)  # AI can override
            except Exception as e:
                log.debug(f"Claude API error: {e}")

        return threat

    def _rule_based_check(self, event: dict) -> Optional[str]:
        """Fast rule-based risk determination without API calls."""
        event_type = event.get("type", "")
        count = event.get("count", 0)

        rules = {
            "BRUTE_FORCE": "CRITICAL" if count >= 50 else "HIGH",
            "PORT_SCAN": "HIGH",
            "WEB_SCAN": "MEDIUM" if count < 100 else "HIGH",
            "SUSPICIOUS_PROCESS": "CRITICAL",
            "FILE_CHANGE": "HIGH",
        }
        return rules.get(event_type)

    async def _claude_analyze(self, event: dict) -> dict:
        """Call Claude API for deep threat analysis."""
        import asyncio

        prompt = f"""You are a senior cybersecurity analyst. Analyze this security event and respond in JSON:

Event: {event}

Respond with exactly this JSON structure:
{{
  "risk": "CRITICAL|HIGH|MEDIUM|LOW",
  "analysis": "2-3 sentence explanation of what this threat is",
  "remediation": "specific command or action to take immediately",
  "false_positive_likely": true/false
}}

Be specific, concise, and actionable."""

        # Run sync anthropic call in thread pool
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None,
            lambda: self.client.messages.create(
                model=os.getenv("AI_MODEL", "claude-3-5-sonnet-20241022"),
                max_tokens=400,
                messages=[{"role": "user", "content": prompt}],
            )
        )

        import json
        text = response.content[0].text
        # Extract JSON from response
        start = text.find("{")
        end = text.rfind("}") + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
        return {"risk": "HIGH", "analysis": text, "remediation": "Review manually"}
