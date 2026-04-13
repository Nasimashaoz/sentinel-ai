"""
Sentinel AI — File Integrity Monitor
Watches critical system files for unauthorized changes using SHA-256 hashing.
Alerts immediately when any monitored file is modified, created, or deleted.
"""

import asyncio
import hashlib
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

log = logging.getLogger(__name__)

# Default critical files to monitor
DEFAULT_MONITORED_FILES = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/etc/hosts",
    "/root/.bashrc",
    "/root/.ssh/authorized_keys",
    "/etc/systemd/system",
]


class FileIntegrityMonitor:
    def __init__(self, baseline_file: str = "data/fim_baseline.json"):
        self.baseline_file = Path(baseline_file)
        self.baseline_file.parent.mkdir(exist_ok=True)
        self.baseline: Dict[str, str] = {}
        self.monitored_files = [
            f.strip() for f in
            os.getenv("FIM_PATHS", ",".join(DEFAULT_MONITORED_FILES)).split(",")
            if f.strip()
        ]
        self._load_baseline()

    def _hash_file(self, path: str) -> Optional[str]:
        try:
            h = hashlib.sha256()
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h.update(chunk)
            return h.hexdigest()
        except (PermissionError, FileNotFoundError):
            return None

    def _load_baseline(self):
        if self.baseline_file.exists():
            try:
                self.baseline = json.loads(self.baseline_file.read_text())
                log.info(f"FIM baseline loaded: {len(self.baseline)} files")
            except Exception:
                self.baseline = {}
        else:
            log.info("FIM: No baseline found — creating now")
            self._save_baseline(self._build_baseline())

    def _build_baseline(self) -> dict:
        baseline = {}
        for path in self.monitored_files:
            h = self._hash_file(path)
            if h:
                baseline[path] = h
                log.debug(f"FIM baseline: {path} = {h[:12]}...")
        return baseline

    def _save_baseline(self, baseline: dict):
        self.baseline = baseline
        self.baseline_file.write_text(json.dumps(baseline, indent=2))
        log.info(f"FIM baseline saved: {len(baseline)} files")

    async def scan(self) -> list:
        """Scan monitored files and return list of change events."""
        events = []
        if not self.baseline:
            self._save_baseline(self._build_baseline())
            return []

        for path in self.monitored_files:
            current_hash = self._hash_file(path)
            stored_hash = self.baseline.get(path)

            if stored_hash and current_hash is None:
                # File deleted
                events.append({
                    "type": "FILE_DELETED",
                    "source_ip": "localhost",
                    "service": "FIM",
                    "path": path,
                    "raw": f"DELETED: {path}",
                })
                log.warning(f"FIM: {path} was DELETED")

            elif current_hash and stored_hash is None:
                # New file appeared
                events.append({
                    "type": "FILE_CREATED",
                    "source_ip": "localhost",
                    "service": "FIM",
                    "path": path,
                    "raw": f"CREATED: {path}",
                })
                self.baseline[path] = current_hash
                log.warning(f"FIM: {path} was CREATED")

            elif current_hash and stored_hash and current_hash != stored_hash:
                # File modified
                events.append({
                    "type": "FILE_MODIFIED",
                    "source_ip": "localhost",
                    "service": "FIM",
                    "path": path,
                    "old_hash": stored_hash[:16],
                    "new_hash": current_hash[:16],
                    "raw": f"MODIFIED: {path} | {stored_hash[:12]} → {current_hash[:12]}",
                })
                # Update baseline after alerting
                self.baseline[path] = current_hash
                self._save_baseline(self.baseline)
                log.warning(f"FIM: {path} was MODIFIED")

        return events

    def rebaseline(self):
        """Rebuild the baseline from current state (use after intentional changes)."""
        new_baseline = self._build_baseline()
        self._save_baseline(new_baseline)
        log.info(f"FIM rebaselined: {len(new_baseline)} files")
        return new_baseline
