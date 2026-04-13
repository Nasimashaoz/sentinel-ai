"""
Sentinel AI — Compliance Check Engine
Runs automated OWASP / NIST / ISO 27001 checks on the host.
"""

import logging
import os
import subprocess
from pathlib import Path

log = logging.getLogger(__name__)


class ComplianceEngine:
    def run_all(self) -> dict:
        return {
            "ssh_hardening": self._check_ssh(),
            "password_policy": self._check_password_policy(),
            "firewall": self._check_firewall(),
            "auto_updates": self._check_auto_updates(),
            "fail2ban": self._check_fail2ban(),
        }

    def _check_ssh(self) -> dict:
        findings = []
        sshd = Path("/etc/ssh/sshd_config")
        if sshd.exists():
            content = sshd.read_text(errors="ignore")
            if "PermitRootLogin yes" in content:
                findings.append("Root SSH login is ENABLED — disable with PermitRootLogin no")
            if "PasswordAuthentication yes" in content:
                findings.append("Password auth enabled — use key-based auth only")
            if "#MaxAuthTries" in content or "MaxAuthTries" not in content:
                findings.append("MaxAuthTries not set — add MaxAuthTries 3")
        return {"pass": len(findings) == 0, "findings": findings}

    def _check_password_policy(self) -> dict:
        findings = []
        login_defs = Path("/etc/login.defs")
        if login_defs.exists():
            content = login_defs.read_text(errors="ignore")
            if "PASS_MAX_DAYS" not in content:
                findings.append("Password max age not configured")
            if "PASS_MIN_LEN" not in content:
                findings.append("Minimum password length not set")
        return {"pass": len(findings) == 0, "findings": findings}

    def _check_firewall(self) -> dict:
        findings = []
        try:
            result = subprocess.run(["ufw", "status"], capture_output=True, text=True, timeout=5)
            if "inactive" in result.stdout.lower():
                findings.append("UFW firewall is INACTIVE")
        except FileNotFoundError:
            try:
                result = subprocess.run(["firewall-cmd", "--state"], capture_output=True, text=True, timeout=5)
                if "not running" in result.stdout:
                    findings.append("firewalld is not running")
            except FileNotFoundError:
                findings.append("No firewall detected (UFW/firewalld)")
        except Exception:
            pass
        return {"pass": len(findings) == 0, "findings": findings}

    def _check_auto_updates(self) -> dict:
        findings = []
        unattended = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        if not unattended.exists():
            findings.append("Unattended upgrades not configured")
        return {"pass": len(findings) == 0, "findings": findings}

    def _check_fail2ban(self) -> dict:
        findings = []
        try:
            result = subprocess.run(["systemctl", "is-active", "fail2ban"], capture_output=True, text=True, timeout=5)
            if "active" not in result.stdout:
                findings.append("fail2ban is not running")
        except Exception:
            findings.append("fail2ban not installed")
        return {"pass": len(findings) == 0, "findings": findings}
