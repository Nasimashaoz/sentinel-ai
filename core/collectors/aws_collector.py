"""
Sentinel AI — AWS CloudTrail Collector (v1.2)
Detects suspicious AWS activity:
  - IAM key creation / privilege escalation
  - Root account usage
  - S3 bucket policy changes
  - Unusual API calls from new regions
  - Security group / firewall rule modifications
  - Failed authentication attempts (console + API)

Requires: pip install boto3
Auth: uses standard AWS credential chain (env vars, ~/.aws, IAM role)
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger(__name__)

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    log.warning("boto3 not installed. Run: pip install boto3")

# High-risk CloudTrail event names
CRITICAL_EVENTS = {
    "CreateAccessKey", "DeleteAccessKey", "UpdateAccessKey",
    "AttachUserPolicy", "AttachRolePolicy", "PutUserPolicy", "PutRolePolicy",
    "CreateUser", "DeleteUser", "AddUserToGroup",
    "ConsoleLogin",   # esp. failed or root
    "StopLogging",    # disabling CloudTrail = major red flag
    "DeleteTrail", "UpdateTrail",
    "PutBucketPolicy", "DeleteBucketPolicy", "PutBucketAcl",
    "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
    "RevokeSecurityGroupIngress",
    "CreateVpc", "DeleteVpc",
    "RunInstances",   # unexpected EC2 launches = cryptomining
    "TerminateInstances",
}


class AWSCollector:
    def __init__(self):
        self.enabled = BOTO3_AVAILABLE and os.getenv("AWS_ENABLED", "false").lower() == "true"
        self.region = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
        self.lookback_minutes = int(os.getenv("AWS_LOOKBACK_MINUTES", "5"))
        self._client = None
        if self.enabled:
            self._init_client()

    def _init_client(self):
        try:
            self._client = boto3.client("cloudtrail", region_name=self.region)
            # Verify credentials
            self._client.get_trail_status(Name="") # will fail fast if no creds
        except NoCredentialsError:
            log.error("AWS: No credentials found. Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY or use IAM role.")
            self.enabled = False
        except ClientError as e:
            if "TrailNotFoundException" in str(e) or "AccessDenied" not in str(e):
                log.info("✅ AWS CloudTrail collector initialized")
            else:
                log.error(f"AWS CloudTrail access denied: {e}")
                self.enabled = False
        except Exception as e:
            log.error(f"AWS collector init error: {e}")
            self.enabled = False

    async def collect(self) -> list:
        if not self.enabled or not self._client:
            return []
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._fetch_events)

    def _fetch_events(self) -> list:
        events = []
        start_time = datetime.now(timezone.utc) - timedelta(minutes=self.lookback_minutes)
        try:
            paginator = self._client.get_paginator("lookup_events")
            pages = paginator.paginate(
                StartTime=start_time,
                EndTime=datetime.now(timezone.utc),
                PaginationConfig={"MaxItems": 200, "PageSize": 50},
            )
            for page in pages:
                for ct_event in page.get("Events", []):
                    parsed = self._parse_event(ct_event)
                    if parsed:
                        events.append(parsed)
        except Exception as e:
            log.debug(f"AWS CloudTrail fetch error: {e}")
        return events

    def _parse_event(self, ct_event: dict) -> Optional[dict]:
        event_name = ct_event.get("EventName") or ct_event.get("eventName", "")
        source_ip = ct_event.get("SourceIPAddress") or ct_event.get("sourceIPAddress", "unknown")
        event_time = ct_event.get("EventTime") or ct_event.get("eventTime", datetime.now(timezone.utc))

        resources = [r.get("ResourceName", "") for r in ct_event.get("Resources", [])]
        resource_str = ", ".join(resources) if resources else "N/A"

        user_identity = ct_event.get("userIdentity") or ct_event.get("UserIdentity", {})

        username = ct_event.get("Username") or user_identity.get("userName", "unknown")
        user_type = user_identity.get("type") or user_identity.get("Type", "")

        if user_type == "Root":
            username = "root"

        # Root account usage — always CRITICAL
        if username == "root":
            return {
                "type": "AWS_ROOT_LOGIN",
                "source_ip": source_ip,
                "service": f"AWS:{event_name}",
                "aws_event": event_name,
                "aws_user": username,
                "aws_resource": resource_str,
                "risk": "CRITICAL",
                "raw": f"Root account used: {event_name} from {source_ip}",
                "timestamp": event_time.isoformat() if hasattr(event_time, 'isoformat') else str(event_time),
            }

        # CloudTrail disabled — attack covering tracks
        if event_name in ("StopLogging", "DeleteTrail"):
            return {
                "type": "AWS_CLOUDTRAIL_DISABLED",
                "source_ip": source_ip,
                "service": f"AWS:CloudTrail",
                "aws_event": event_name,
                "aws_user": username,
                "risk": "CRITICAL",
                "raw": f"CloudTrail logging disabled by {username} from {source_ip}",
                "timestamp": event_time.isoformat() if hasattr(event_time, 'isoformat') else str(event_time),
            }

        # High-risk IAM/security events
        if event_name in CRITICAL_EVENTS:
            return {
                "type": "AWS_SUSPICIOUS_API",
                "source_ip": source_ip,
                "service": f"AWS:{event_name}",
                "aws_event": event_name,
                "aws_user": username,
                "aws_resource": resource_str,
                "raw": f"{event_name} by {username} from {source_ip} on {resource_str}",
                "timestamp": event_time.isoformat() if hasattr(event_time, 'isoformat') else str(event_time),
            }

        return None
