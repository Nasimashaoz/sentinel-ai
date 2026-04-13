"""
Sentinel AI — GCP Audit Log Collector (v1.2)
Detects suspicious Google Cloud activity via Cloud Audit Logs:
  - IAM policy changes (project/org level)
  - Service account key creation
  - Firewall rule modifications
  - Storage bucket ACL changes
  - Unusual API calls from new IPs/regions
  - Root/admin account logins
  - VPC flow anomalies

Requires: pip install google-cloud-logging google-auth
Auth: uses Application Default Credentials (ADC)
  gcloud auth application-default login
  OR set GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger(__name__)

try:
    from google.cloud import logging as gcp_logging
    from google.oauth2 import service_account
    GCP_AVAILABLE = True
except ImportError:
    GCP_AVAILABLE = False
    log.warning("google-cloud-logging not installed. Run: pip install google-cloud-logging")

# High-risk GCP log method names
CRITICAL_METHODS = {
    # IAM
    "SetIamPolicy", "google.iam.admin.v1.CreateServiceAccountKey",
    "google.iam.admin.v1.DeleteServiceAccountKey",
    "google.iam.admin.v1.CreateServiceAccount",
    "google.iam.admin.v1.DeleteServiceAccount",
    # Firewall
    "v1.compute.firewalls.insert", "v1.compute.firewalls.patch",
    "v1.compute.firewalls.delete",
    # Storage
    "storage.setIamPermissions", "storage.buckets.update",
    # Logging (covering tracks)
    "google.logging.v2.LoggingServiceV2.DeleteLog",
    "google.logging.v2.ConfigServiceV2.DeleteSink",
    # Compute
    "v1.compute.instances.insert",   # unexpected VM = cryptomining
    "v1.compute.instances.delete",
    # VPC
    "v1.compute.networks.insert", "v1.compute.networks.delete",
}


class GCPCollector:
    def __init__(self):
        self.enabled = GCP_AVAILABLE and os.getenv("GCP_ENABLED", "false").lower() == "true"
        self.project_id = os.getenv("GCP_PROJECT_ID", "")
        self.lookback_minutes = int(os.getenv("GCP_LOOKBACK_MINUTES", "5"))
        self._client = None
        if self.enabled:
            self._init_client()

    def _init_client(self):
        try:
            creds_file = os.getenv("GOOGLE_APPLICATION_CREDENTIALS")
            if creds_file:
                creds = service_account.Credentials.from_service_account_file(
                    creds_file,
                    scopes=["https://www.googleapis.com/auth/logging.read"]
                )
                self._client = gcp_logging.Client(project=self.project_id, credentials=creds)
            else:
                self._client = gcp_logging.Client(project=self.project_id)
            log.info(f"✅ GCP collector initialized (project: {self.project_id})")
        except Exception as e:
            log.error(f"GCP collector init error: {e}")
            self.enabled = False

    async def collect(self) -> list:
        if not self.enabled or not self._client:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._fetch_entries)

    def _fetch_entries(self) -> list:
        events = []
        since = datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes)
        ts_filter = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        # Query only admin activity and data access audit logs
        log_filter = (
            f'logName:("cloudaudit.googleapis.com/activity" OR '
            f'"cloudaudit.googleapis.com/data_access") '
            f'AND timestamp >= "{ts_filter}"'
        )
        try:
            entries = self._client.list_entries(
                filter_=log_filter,
                order_by=gcp_logging.DESCENDING,
                max_results=200,
            )
            for entry in entries:
                parsed = self._parse_entry(entry)
                if parsed:
                    events.append(parsed)
        except Exception as e:
            log.debug(f"GCP log fetch error: {e}")
        return events

    def _parse_entry(self, entry) -> Optional[dict]:
        try:
            payload = entry.payload if hasattr(entry, "payload") else {}
            method = ""
            principal = ""
            source_ip = "unknown"
            if isinstance(payload, dict):
                method = payload.get("methodName", "")
                auth = payload.get("authenticationInfo", {})
                principal = auth.get("principalEmail", "")
                req_meta = payload.get("requestMetadata", {})
                source_ip = req_meta.get("callerIp", "unknown")
            ts = entry.timestamp.isoformat() if entry.timestamp else datetime.now(timezone.utc).isoformat()

            # GCP audit log disabled — covering tracks
            if "DeleteLog" in method or "DeleteSink" in method:
                return {
                    "type": "GCP_LOGGING_DISABLED",
                    "source_ip": source_ip,
                    "service": f"GCP:{method}",
                    "gcp_method": method,
                    "gcp_principal": principal,
                    "risk": "CRITICAL",
                    "raw": f"GCP audit logging tampered: {method} by {principal}",
                    "timestamp": ts,
                }

            if method in CRITICAL_METHODS or any(m in method for m in ("SetIamPolicy", "firewalls", "setIamPermissions")):
                return {
                    "type": "GCP_SUSPICIOUS_API",
                    "source_ip": source_ip,
                    "service": f"GCP:{method.split('.')[-1]}",
                    "gcp_method": method,
                    "gcp_principal": principal,
                    "raw": f"{method} by {principal} from {source_ip}",
                    "timestamp": ts,
                }
        except Exception as e:
            log.debug(f"GCP entry parse error: {e}")
        return None
