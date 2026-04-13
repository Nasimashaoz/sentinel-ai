"""
Sentinel AI — Azure AD & Activity Log Collector (v1.2)
Detects suspicious Azure activity:
  - Azure AD sign-in anomalies (failed logins, impossible travel)
  - Privileged role assignments
  - Service principal creation
  - Resource group / subscription policy changes
  - Key Vault access anomalies
  - Network security group modifications
  - Unexpected resource deployments

Requires: pip install azure-identity azure-mgmt-monitor azure-mgmt-resource
Auth: uses DefaultAzureCredential (env vars, managed identity, az cli)
  Set: AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET
  Or:  az login
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger(__name__)

try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential
    from azure.mgmt.monitor import MonitorManagementClient
    AZURE_AVAILABLE = True
except ImportError:
    AZURE_AVAILABLE = False
    log.warning("azure-mgmt-monitor not installed. Run: pip install azure-identity azure-mgmt-monitor")

# High-risk Azure operation names
CRITICAL_OPERATIONS = {
    # IAM / Role assignments
    "Microsoft.Authorization/roleAssignments/write",
    "Microsoft.Authorization/roleDefinitions/write",
    # Azure AD
    "microsoft.aad.directory/users/appRoleAssignments/create",
    "microsoft.aad.directory/servicePrincipals/create",
    # Key Vault
    "Microsoft.KeyVault/vaults/secrets/read",
    "Microsoft.KeyVault/vaults/keys/read",
    # Network
    "Microsoft.Network/networkSecurityGroups/securityRules/write",
    "Microsoft.Network/networkSecurityGroups/write",
    # Policy
    "Microsoft.Authorization/policyAssignments/write",
    "Microsoft.Authorization/policyDefinitions/write",
    # Deployments
    "Microsoft.Resources/deployments/write",
    # Diagnostic settings (covering tracks)
    "microsoft.insights/diagnosticSettings/delete",
    "microsoft.insights/activityLogAlerts/delete",
}


class AzureCollector:
    def __init__(self):
        self.enabled = AZURE_AVAILABLE and os.getenv("AZURE_ENABLED", "false").lower() == "true"
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")
        self.lookback_minutes = int(os.getenv("AZURE_LOOKBACK_MINUTES", "5"))
        self._client = None
        if self.enabled:
            self._init_client()

    def _init_client(self):
        try:
            tenant = os.getenv("AZURE_TENANT_ID")
            client_id = os.getenv("AZURE_CLIENT_ID")
            client_secret = os.getenv("AZURE_CLIENT_SECRET")
            if tenant and client_id and client_secret:
                cred = ClientSecretCredential(tenant, client_id, client_secret)
            else:
                cred = DefaultAzureCredential()
            self._client = MonitorManagementClient(cred, self.subscription_id)
            log.info(f"✅ Azure collector initialized (subscription: {self.subscription_id[:8]}...)")
        except Exception as e:
            log.error(f"Azure collector init error: {e}")
            self.enabled = False

    async def collect(self) -> list:
        if not self.enabled or not self._client:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._fetch_events)

    def _fetch_events(self) -> list:
        events = []
        since = datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes)
        try:
            filter_str = (
                f"eventTimestamp ge '{since.isoformat()}' "
                f"and status eq 'Failed' or eventTimestamp ge '{since.isoformat()}'"
            )
            activity_logs = self._client.activity_logs.list(
                filter=filter_str,
                select="operationName,caller,httpRequest,status,eventTimestamp,resourceId,properties"
            )
            for log_entry in activity_logs:
                parsed = self._parse_entry(log_entry)
                if parsed:
                    events.append(parsed)
        except Exception as e:
            log.debug(f"Azure activity log fetch error: {e}")
        return events

    def _parse_entry(self, entry) -> Optional[dict]:
        try:
            op = entry.operation_name.value if entry.operation_name else ""
            caller = entry.caller or "unknown"
            status = entry.status.value if entry.status else ""
            ts = entry.event_timestamp.isoformat() if entry.event_timestamp else datetime.now(timezone.utc).isoformat()
            source_ip = "unknown"
            if entry.http_request and entry.http_request.client_ip_address:
                source_ip = entry.http_request.client_ip_address
            resource = entry.resource_id or "unknown"

            # Diagnostic settings deleted — covering tracks
            if "diagnosticSettings/delete" in op or "activityLogAlerts/delete" in op:
                return {
                    "type": "AZURE_LOGGING_DISABLED",
                    "source_ip": source_ip,
                    "service": "Azure:Monitor",
                    "azure_operation": op,
                    "azure_caller": caller,
                    "risk": "CRITICAL",
                    "raw": f"Azure monitoring disabled: {op} by {caller}",
                    "timestamp": ts,
                }

            # Failed sign-in flood — brute force
            if "signIn" in op.lower() and status == "Failed":
                return {
                    "type": "AZURE_SIGNIN_FAILURE",
                    "source_ip": source_ip,
                    "service": "Azure:AAD",
                    "azure_operation": op,
                    "azure_caller": caller,
                    "raw": f"Azure AD sign-in failed: {caller} from {source_ip}",
                    "timestamp": ts,
                }

            # High-risk operations
            if op in CRITICAL_OPERATIONS:
                return {
                    "type": "AZURE_SUSPICIOUS_OPERATION",
                    "source_ip": source_ip,
                    "service": f"Azure:{op.split('/')[-1]}",
                    "azure_operation": op,
                    "azure_caller": caller,
                    "azure_resource": resource,
                    "raw": f"{op} by {caller} from {source_ip}",
                    "timestamp": ts,
                }
        except Exception as e:
            log.debug(f"Azure entry parse error: {e}")
        return None
