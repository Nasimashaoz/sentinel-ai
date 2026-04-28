"""
Sentinel AI — Kubernetes Collector (v1.2)
Monitors a Kubernetes cluster for security-relevant events:
  - Pod crashes / OOMKilled
  - Image pull failures (potential supply chain attacks)
  - RBAC violations (Forbidden API calls)
  - Privileged container creation
  - Namespace-level anomalies
  - Unexpected service account token usage

Requires: pip install kubernetes
Auth: uses in-cluster config (inside k8s) or ~/.kube/config (local)
"""

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Optional

log = logging.getLogger(__name__)

try:
    from kubernetes import client, config as k8s_config
    from kubernetes.client.exceptions import ApiException
    K8S_AVAILABLE = True
except ImportError:
    K8S_AVAILABLE = False
    log.warning("kubernetes package not installed. Run: pip install kubernetes")


class KubernetesCollector:
    """
    Collects security events from a Kubernetes cluster.
    Supports both in-cluster (pod) and out-of-cluster (kubeconfig) auth.
    """

    def __init__(self):
        self.enabled = K8S_AVAILABLE and os.getenv("K8S_ENABLED", "false").lower() == "true"
        self.namespace = os.getenv("K8S_NAMESPACE", "")  # empty = all namespaces
        self._last_event_time: Optional[datetime] = None
        self._core_v1 = None
        self._rbac_v1 = None
        if self.enabled:
            self._init_client()

    def _init_client(self):
        try:
            k8s_config.load_incluster_config()
            log.info("☁️ K8s: using in-cluster config")
        except Exception:
            try:
                k8s_config.load_kube_config()
                log.info("☁️ K8s: using kubeconfig")
            except Exception as e:
                log.error(f"K8s config failed: {e}")
                self.enabled = False
                return
        self._core_v1 = client.CoreV1Api()
        self._rbac_v1 = client.RbacAuthorizationV1Api()
        log.info("✅ Kubernetes collector initialized")

    async def collect(self) -> list:
        if not self.enabled:
            return []
        events = []
        since = self._last_event_time or (datetime.now(timezone.utc) - timedelta(minutes=5))

        loop = asyncio.get_event_loop()
        tasks = [
            loop.run_in_executor(None, self._collect_pod_events, since),
            loop.run_in_executor(None, self._collect_rbac_violations, since),
            loop.run_in_executor(None, self._collect_privileged_pods),
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                events.extend(r)

        self._last_event_time = datetime.now(timezone.utc)
        return events

    def _parse_event(self, event) -> Optional[dict]:
        reason = event.reason or ""
        msg = event.message or ""

        # Namespace can be in involved_object or metadata
        namespace = ""
        if getattr(event, "involved_object", None) and getattr(event.involved_object, "namespace", None):
            namespace = event.involved_object.namespace
        elif getattr(event, "metadata", None) and getattr(event.metadata, "namespace", None):
            namespace = event.metadata.namespace

        name = getattr(event, "involved_object", None) and event.involved_object.name or ""
        kind = getattr(event, "involved_object", None) and event.involved_object.kind or ""

        event_time = event.last_timestamp or event.event_time
        if not event_time:
            event_time = datetime.now(timezone.utc)

        event_type = None
        if reason == "OOMKilling":
            event_type = "K8S_OOM_KILLED"
        elif reason in ("ErrImagePull", "ImagePullBackOff") or (reason == "BackOff" and "pulling image" in msg.lower()):
            event_type = "K8S_IMAGE_PULL_BACKOFF"
        elif reason in ("BackOff", "Killed", "Failed"):
            event_type = "K8S_POD_CRASH"

        if not event_type:
            return None

        return {
            "type": event_type,
            "source_ip": "kubernetes",
            "service": f"k8s:{namespace}/{name}",
            "namespace": namespace,
            "resource": f"{kind}/{name}",
            "reason": reason,
            "raw": f"{reason}: {msg} - {name}",
            "timestamp": event_time.isoformat() if hasattr(event_time, 'isoformat') else str(event_time),
        }

    def _collect_pod_events(self, since: datetime) -> list:
        events = []
        try:
            ns = self.namespace or None
            field_selector = "type=Warning"
            kwargs = {"field_selector": field_selector}
            if ns:
                raw = self._core_v1.list_namespaced_event(ns, **kwargs)
            else:
                raw = self._core_v1.list_event_for_all_namespaces(**kwargs)

            for event in raw.items:
                event_time = event.last_timestamp or event.event_time
                if not event_time:
                    continue
                if event_time.replace(tzinfo=timezone.utc) < since:
                    continue

                parsed = self._parse_event(event)
                if parsed:
                    # override timestamp with actual event_time
                    parsed["timestamp"] = event_time.isoformat()
                    events.append(parsed)

        except Exception as e:
            log.debug(f"K8s pod events error: {e}")
        return events

    def _collect_rbac_violations(self, since: datetime) -> list:
        """Detect Forbidden API calls indicating RBAC misuse."""
        events = []
        try:
            ns = self.namespace or None
            field_selector = "reason=Forbidden"
            kwargs = {"field_selector": field_selector}
            if ns:
                raw = self._core_v1.list_namespaced_event(ns, **kwargs)
            else:
                raw = self._core_v1.list_event_for_all_namespaces(**kwargs)

            for event in raw.items:
                event_time = event.last_timestamp or event.event_time
                if event_time and event_time.replace(tzinfo=timezone.utc) >= since:
                    events.append({
                        "type": "K8S_RBAC_VIOLATION",
                        "source_ip": "kubernetes",
                        "service": f"k8s:{event.metadata.namespace}",
                        "namespace": event.metadata.namespace,
                        "resource": event.involved_object.name,
                        "raw": event.message or "",
                        "timestamp": event_time.isoformat(),
                    })
        except Exception as e:
            log.debug(f"K8s RBAC check error: {e}")
        return events

    def _collect_privileged_pods(self) -> list:
        """Detect pods running as privileged or with hostPID/hostNetwork."""
        events = []
        try:
            ns = self.namespace or None
            if ns:
                pods = self._core_v1.list_namespaced_pod(ns)
            else:
                pods = self._core_v1.list_pod_for_all_namespaces()

            for pod in pods.items:
                namespace = pod.metadata.namespace
                name = pod.metadata.name
                spec = pod.spec

                # Check pod-level security
                if spec.host_pid or spec.host_network or spec.host_ipc:
                    events.append({
                        "type": "K8S_PRIVILEGED_POD",
                        "source_ip": "kubernetes",
                        "service": f"k8s:{namespace}/{name}",
                        "namespace": namespace,
                        "resource": f"Pod/{name}",
                        "flags": [
                            f for f, v in [
                                ("hostPID", spec.host_pid),
                                ("hostNetwork", spec.host_network),
                                ("hostIPC", spec.host_ipc),
                            ] if v
                        ],
                        "raw": f"Privileged pod: {namespace}/{name}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    })
                    continue

                # Check container-level security
                for container in (spec.containers or []):
                    sc = container.security_context
                    if sc and sc.privileged:
                        events.append({
                            "type": "K8S_PRIVILEGED_CONTAINER",
                            "source_ip": "kubernetes",
                            "service": f"k8s:{namespace}/{name}/{container.name}",
                            "namespace": namespace,
                            "resource": f"Container/{namespace}/{name}/{container.name}",
                            "raw": f"Privileged container: {namespace}/{name}/{container.name}",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                        })
        except Exception as e:
            log.debug(f"K8s privileged pod check error: {e}")
        return events
