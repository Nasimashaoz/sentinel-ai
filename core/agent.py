"""
Sentinel AI — Main Agent Loop
Orchestrates collection, analysis, and alerting.
"""

import asyncio
import logging
from datetime import datetime, timezone
from typing import List

from core.collector import LogCollector
from core.analyzer import ThreatAnalyzer
from core.scorer import RiskScorer

log = logging.getLogger(__name__)


class SentinelAgent:
    def __init__(self, collector: LogCollector, analyzer: ThreatAnalyzer, alerters: list):
        self.collector = collector
        self.analyzer = analyzer
        self.scorer = RiskScorer()
        self.alerters = alerters
        self.running = False
        self.incidents = []
        self.alert_cooldowns = {}

    async def run(self):
        self.running = True
        log.info("Agent loop started")

        tasks = [
            asyncio.create_task(self._monitor_loop()),
            asyncio.create_task(self._heartbeat()),
        ]
        try:
            await asyncio.gather(*tasks)
        except asyncio.CancelledError:
            pass

    async def stop(self):
        log.info("Shutting down Sentinel AI...")
        self.running = False

    async def _heartbeat(self):
        """Log a heartbeat every 5 minutes to confirm agent is alive."""
        while self.running:
            log.info(f"💚 Sentinel AI alive — {len(self.incidents)} incidents tracked")
            await asyncio.sleep(300)

    async def _monitor_loop(self):
        """Core monitoring loop: collect → analyze → score → remediate → alert."""
        # Initialize RemediationEngine to make use of _is_safe_command
        from core.remediation import RemediationEngine
        remediation_engine = RemediationEngine()

        while self.running:
            try:
                events = await self.collector.collect()
                for event in events:
                    threat = await self.analyzer.analyze(event)
                    if threat:
                        threat["score"] = self.scorer.score(threat)
                        threat["timestamp"] = datetime.now(timezone.utc).isoformat()

                        # Auto-remediation hook
                        if remediation_engine.enabled:
                            remedy_result = await remediation_engine.handle(threat)
                            threat["remediation"] = remedy_result
                            if remedy_result.get("action") == "skipped":
                                # Example use-case: blocklist check or fallback if command isn't in playbook templates
                                if "command" in remedy_result and not remediation_engine._is_safe_command(remedy_result["command"]):
                                    log.warning(f"Prevented execution of non-whitelisted command: {remedy_result['command']}")

                        self.incidents.append(threat)

                        if self._should_alert(threat):
                            await self._send_alerts(threat)

            except Exception as e:
                log.error(f"Monitor loop error: {e}")

            await asyncio.sleep(10)  # Poll every 10 seconds

    def _should_alert(self, threat: dict) -> bool:
        """Deduplicate alerts using cooldown per threat type."""
        import os, time
        key = f"{threat.get('type')}:{threat.get('source_ip', 'unknown')}"
        cooldown = int(os.getenv("CRIT_ALERT_COOLDOWN", 60))
        now = time.time()
        last = self.alert_cooldowns.get(key, 0)
        if now - last > cooldown:
            self.alert_cooldowns[key] = now
            return True
        return False

    async def _send_alerts(self, threat: dict):
        """Send threat alert to all configured channels."""
        tasks = [alerter.send(threat) for alerter in self.alerters]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                log.error(f"Alerter {i} failed: {result}")
            else:
                log.info(f"📨 Alert sent via {self.alerters[i].__class__.__name__}")
