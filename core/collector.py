"""
Sentinel AI — Log & Metric Collectors
Reads SSH auth logs, nginx, syslog, processes, and open ports.
"""

import asyncio
import logging
import os
import re
import subprocess
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

log = logging.getLogger(__name__)


class LogCollector:
    def __init__(self):
        self.failed_logins = defaultdict(list)
        self.last_read_positions = {}
        self.port_scan_tracker = defaultdict(list)
        self.failed_threshold = int(os.getenv("FAILED_LOGIN_THRESHOLD", 5))
        self.port_scan_threshold = int(os.getenv("PORT_SCAN_THRESHOLD", 20))

    async def collect(self) -> list:
        events = []
        if os.getenv("MONITOR_SSH", "true").lower() == "true":
            events.extend(await self._collect_ssh_events())
        if os.getenv("MONITOR_NGINX", "true").lower() == "true":
            events.extend(await self._collect_nginx_events())
        if os.getenv("MONITOR_PROCESSES", "true").lower() == "true":
            events.extend(await self._collect_process_events())
        if os.getenv("MONITOR_PORTS", "true").lower() == "true":
            events.extend(await self._collect_port_events())
        return events

    async def _collect_ssh_events(self) -> list:
        events = []
        auth_log = Path("/var/log/auth.log")
        if not auth_log.exists():
            auth_log = Path("/var/log/secure")  # RHEL/CentOS
        if not auth_log.exists():
            return events

        try:
            new_lines = self._read_new_lines(str(auth_log))
            fail_pattern = re.compile(
                r"Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
            )
            for line in new_lines:
                match = fail_pattern.search(line)
                if match:
                    ip = match.group(1)
                    self.failed_logins[ip].append(datetime.utcnow())
                    # Keep only last 5 min
                    cutoff = datetime.utcnow() - timedelta(minutes=5)
                    self.failed_logins[ip] = [
                        t for t in self.failed_logins[ip] if t > cutoff
                    ]
                    if len(self.failed_logins[ip]) >= self.failed_threshold:
                        events.append({
                            "type": "BRUTE_FORCE",
                            "source_ip": ip,
                            "count": len(self.failed_logins[ip]),
                            "service": "SSH",
                            "raw": line.strip(),
                        })
                        self.failed_logins[ip] = []  # Reset after alert
        except Exception as e:
            log.debug(f"SSH collect error: {e}")
        return events

    async def _collect_nginx_events(self) -> list:
        events = []
        nginx_log = Path("/var/log/nginx/access.log")
        if not nginx_log.exists():
            return events
        try:
            new_lines = self._read_new_lines(str(nginx_log))
            error_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+).*" (4[0-9]{2}|5[0-9]{2})')
            error_counts = defaultdict(int)
            for line in new_lines:
                match = error_pattern.search(line)
                if match:
                    ip, status = match.group(1), match.group(2)
                    error_counts[ip] += 1
            for ip, count in error_counts.items():
                if count >= 20:
                    events.append({
                        "type": "WEB_SCAN",
                        "source_ip": ip,
                        "count": count,
                        "service": "NGINX",
                        "raw": f"{count} error responses to {ip}",
                    })
        except Exception as e:
            log.debug(f"Nginx collect error: {e}")
        return events

    async def _collect_process_events(self) -> list:
        events = []
        suspicious = [
            "nmap", "masscan", "hydra", "metasploit", "msfconsole",
            "netcat", "nc -l", "bash -i", "python -c", "perl -e",
            "curl | bash", "wget | sh",
        ]
        try:
            result = subprocess.run(
                ["ps", "aux"], capture_output=True, text=True, timeout=5
            )
            for line in result.stdout.splitlines():
                for s in suspicious:
                    if s in line.lower():
                        events.append({
                            "type": "SUSPICIOUS_PROCESS",
                            "source_ip": "localhost",
                            "process": line.strip(),
                            "match": s,
                            "raw": line.strip(),
                        })
        except Exception as e:
            log.debug(f"Process collect error: {e}")
        return events

    async def _collect_port_events(self) -> list:
        events = []
        try:
            result = subprocess.run(
                ["ss", "-tn", "state", "established"],
                capture_output=True, text=True, timeout=5
            )
            ip_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+):(\d+)")
            ip_counts = defaultdict(int)
            for line in result.stdout.splitlines()[1:]:
                matches = ip_pattern.findall(line)
                for ip, port in matches:
                    if not ip.startswith(("127.", "10.", "192.168.", "::1")):
                        ip_counts[ip] += 1
            for ip, count in ip_counts.items():
                if count >= self.port_scan_threshold:
                    events.append({
                        "type": "PORT_SCAN",
                        "source_ip": ip,
                        "count": count,
                        "service": "NETWORK",
                        "raw": f"{count} connections from {ip}",
                    })
        except Exception as e:
            log.debug(f"Port collect error: {e}")
        return events

    def _read_new_lines(self, path: str) -> list:
        """Read only new lines since last read (tail-like behavior)."""
        try:
            with open(path, "r", errors="ignore") as f:
                pos = self.last_read_positions.get(path, 0)
                f.seek(0, 2)  # End of file
                end = f.tell()
                if pos == 0:
                    pos = max(0, end - 4096)  # Start from last 4KB
                f.seek(pos)
                lines = f.readlines()
                self.last_read_positions[path] = end
                return lines
        except Exception:
            return []
