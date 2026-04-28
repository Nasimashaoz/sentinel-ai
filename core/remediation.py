"""
Sentinel AI — Auto-Remediation Engine (v2.0 preview)
Automatically executes safe remediation actions for confirmed threats.

Safety model:
  - WHITELIST-only: only pre-approved actions are ever executed
  - DRY_RUN mode by default: logs what WOULD be done, never executes
  - Confirmation required for CRITICAL actions (unless AUTO_REMEDIATE_CRITICAL=true)
  - Full audit log of every action attempted
  - Rollback commands stored alongside every action

Enable: AUTO_REMEDIATE=true in .env
Dry run (default): AUTO_REMEDIATE=false  (logs actions without executing)
"""

import asyncio
import logging
import os
import subprocess
from datetime import datetime
from pathlib import Path
import json

log = logging.getLogger(__name__)

AUTO_REMEDIATE = os.getenv("AUTO_REMEDIATE", "false").lower() == "true"
AUTO_REMEDIATE_CRITICAL = os.getenv("AUTO_REMEDIATE_CRITICAL", "false").lower() == "true"
AUDIT_LOG = Path("data/remediation_audit.jsonl")
AUDIT_LOG.parent.mkdir(exist_ok=True)

# Whitelist of safe auto-remediation commands per threat type
# Format: threat_type -> {"command": ..., "rollback": ..., "description": ...}
REMEDIATION_PLAYBOOK = {
    "BRUTE_FORCE": {
        "command": "fail2ban-client set sshd banip {source_ip}",
        "rollback": "fail2ban-client set sshd unbanip {source_ip}",
        "description": "Ban IP in fail2ban for SSH brute force",
        "safe_for_auto": True,
    },
    "PORT_SCAN": {
        "command": "iptables -A INPUT -s {source_ip} -j DROP",
        "rollback": "iptables -D INPUT -s {source_ip} -j DROP",
        "description": "Block IP in iptables for port scan",
        "safe_for_auto": True,
    },
    "WEB_SCAN": {
        "command": "iptables -A INPUT -s {source_ip} -j DROP",
        "rollback": "iptables -D INPUT -s {source_ip} -j DROP",
        "description": "Block IP for web scanning",
        "safe_for_auto": True,
    },
    "SUSPICIOUS_PROCESS": {
        "command": "kill -9 {pid}",
        "rollback": None,  # cannot undo kill
        "description": "Kill suspicious process",
        "safe_for_auto": False,  # requires human confirmation
    },
    "K8S_PRIVILEGED_CONTAINER": {
        "command": "kubectl delete pod {resource} -n {namespace} --force --grace-period=0",
        "rollback": None,
        "description": "Force delete privileged Kubernetes pod",
        "safe_for_auto": False,
    },
    "AWS_ROOT_USAGE": {
        "command": None,  # cannot auto-block AWS root
        "rollback": None,
        "description": "Alert only — AWS root cannot be auto-blocked",
        "safe_for_auto": False,
    },
}


class RemediationEngine:
    def __init__(self):
        self.dry_run = not AUTO_REMEDIATE
        if self.dry_run:
            log.info("🔒 Remediation: DRY RUN mode (set AUTO_REMEDIATE=true to enable)")
        else:
            log.warning("⚠️ Remediation: LIVE mode — will execute commands automatically")

    async def handle(self, threat: dict) -> dict:
        """Attempt remediation for a threat. Returns action result."""
        t_type = threat.get("type", "")
        risk = threat.get("risk", "LOW")
        playbook = REMEDIATION_PLAYBOOK.get(t_type)

        if not playbook or not playbook.get("command"):
            return {"action": "none", "reason": "No playbook for this threat type"}

        # Build the command
        try:
            cmd = playbook["command"].format(
                source_ip=threat.get("source_ip", ""),
                pid=threat.get("pid", ""),
                resource=threat.get("resource", ""),
                namespace=threat.get("namespace", "default"),
            )
        except KeyError as e:
            return {"action": "none", "reason": f"Missing template variable: {e}"}

        rollback = None
        if playbook.get("rollback"):
            try:
                rollback = playbook["rollback"].format(
                    source_ip=threat.get("source_ip", ""),
                )
            except Exception:
                pass

        # Safety gate
        safe = playbook.get("safe_for_auto", False)
        critical_ok = AUTO_REMEDIATE_CRITICAL or risk not in ("CRITICAL",)

        # Verify the command matches the whitelist
        if not self._is_safe_command(cmd):
            return {
                "action": "skipped",
                "reason": "Command failed safety whitelist check",
                "command": cmd
            }

        if self.dry_run:
            result = self._dry_run(cmd, rollback, playbook["description"])
        elif safe and critical_ok:
            result = await self._execute(cmd, rollback, playbook["description"])
        else:
            result = {
                "action": "skipped",
                "reason": f"Manual approval required (safe={safe}, risk={risk})",
                "command": cmd,
                "rollback": rollback,
            }

        self._audit(threat, cmd, rollback, result)
        return result

    def _dry_run(self, cmd: str, rollback: str, description: str) -> dict:
        log.info(f"🔍 DRY RUN — would execute: {cmd}")
        return {"action": "dry_run", "command": cmd, "rollback": rollback, "description": description}

    async def _execute(self, cmd: str, rollback: str, description: str) -> dict:
        log.warning(f"⚡ EXECUTING: {cmd}")
        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(
                    cmd, shell=True, capture_output=True, text=True, timeout=10
                )
            )
            success = result.returncode == 0
            log.info(f"Remediation {'succeeded' if success else 'FAILED'}: {cmd}")
            return {
                "action": "executed",
                "command": cmd,
                "rollback": rollback,
                "success": success,
                "stdout": result.stdout[:500],
                "stderr": result.stderr[:500],
            }
        except Exception as e:
            log.error(f"Remediation execution error: {e}")
            return {"action": "error", "command": cmd, "error": str(e)}

    def _is_safe_command(self, cmd: str) -> bool:
        """Check if a given command matches any whitelisted command templates."""
        import re
        for playbook in REMEDIATION_PLAYBOOK.values():
            if playbook.get("command"):
                # Simple check: replace format strings with a generic pattern and match
                pattern = re.sub(r'\{[^}]+\}', '.*', playbook["command"])
                # We want a fairly strict match
                if re.match(f"^{pattern}$", cmd):
                    return True
        return False

    def _audit(self, threat: dict, cmd: str, rollback: str, result: dict):
        entry = {
            "ts": datetime.utcnow().isoformat(),
            "threat_type": threat.get("type"),
            "risk": threat.get("risk"),
            "source_ip": threat.get("source_ip"),
            "command": cmd,
            "rollback": rollback,
            "result": result,
        }
        with open(AUDIT_LOG, "a") as f:
            f.write(json.dumps(entry) + "\n")
