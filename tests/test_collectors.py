"""
Tests for cloud collectors — input parsing and event classification.
All external API calls are mocked.
"""
import pytest
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))


class TestKubernetesCollector:
    def _make_collector(self):
        with patch.dict(os.environ, {"K8S_ENABLED": "false"}):
            from core.collectors.kubernetes_collector import KubernetesCollector
            return KubernetesCollector()

    def test_disabled_returns_empty(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"K8S_ENABLED": "false"}):
            from core.collectors.kubernetes_collector import KubernetesCollector
            c = KubernetesCollector()
            assert c.enabled is False

    def test_parse_oom_killed_event(self):
        from unittest.mock import patch, MagicMock
        from datetime import datetime, timezone
        with patch.dict(os.environ, {"K8S_ENABLED": "false"}):
            from core.collectors.kubernetes_collector import KubernetesCollector
            c = KubernetesCollector()
            c._core_v1 = MagicMock()
            mock_event = MagicMock()
            mock_event.reason = "OOMKilling"
            mock_event.message = "Memory limit exceeded for container app"
            mock_event.involved_object.name = "my-pod-abc123"
            mock_event.involved_object.kind = "Pod"
            mock_event.metadata.namespace = "production"
            mock_event.last_timestamp = datetime.now(timezone.utc)
            mock_event.event_time = None

            c._core_v1.list_event_for_all_namespaces.return_value.items = [mock_event]

            from datetime import timedelta
            since = datetime.now(timezone.utc) - timedelta(minutes=5)

            results = c._collect_pod_events(since)
            assert len(results) == 1
            assert results[0]["type"] == "K8S_POD_CRASH"
            assert "OOMKilling: Memory limit exceeded" in results[0]["raw"]

    def test_parse_image_pull_backoff(self):
        from unittest.mock import patch, MagicMock
        from datetime import datetime, timezone
        with patch.dict(os.environ, {"K8S_ENABLED": "false"}):
            from core.collectors.kubernetes_collector import KubernetesCollector
            c = KubernetesCollector()
            c._core_v1 = MagicMock()
            mock_event = MagicMock()
            mock_event.reason = "ImagePullBackOff"
            mock_event.message = "Back-off pulling image \"private.registry/app:latest\""
            mock_event.involved_object.name = "my-deployment-xyz"
            mock_event.involved_object.kind = "Pod"
            mock_event.metadata.namespace = "default"
            mock_event.last_timestamp = datetime.now(timezone.utc)
            mock_event.event_time = None

            c._core_v1.list_event_for_all_namespaces.return_value.items = [mock_event]

            from datetime import timedelta
            since = datetime.now(timezone.utc) - timedelta(minutes=5)

            results = c._collect_pod_events(since)
            assert len(results) == 1
            assert results[0]["type"] == "K8S_IMAGE_PULL_FAILURE"


class TestAWSCollector:
    def test_disabled_returns_empty(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"AWS_ENABLED": "false"}):
            from core.collectors.aws_collector import AWSCollector
            c = AWSCollector()
            assert c.enabled is False

    def test_parse_root_login(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"AWS_ENABLED": "false"}):
            from core.collectors.aws_collector import AWSCollector
            c = AWSCollector()
            event = {
                "EventName": "ConsoleLogin",
                "Username": "root",
                "SourceIPAddress": "1.2.3.4",
                "EventTime": "2026-04-13T08:00:00Z",
                "Resources": [],
            }
            result = c._parse_event(event)
            assert result is not None
            assert result["type"] == "AWS_ROOT_USAGE"
            assert result["risk"] == "CRITICAL"

    def test_parse_cloudtrail_disabled(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"AWS_ENABLED": "false"}):
            from core.collectors.aws_collector import AWSCollector
            c = AWSCollector()
            event = {
                "EventName": "StopLogging",
                "Username": "hacker",
                "SourceIPAddress": "5.6.7.8",
                "EventTime": "2026-04-13T08:00:00Z",
                "Resources": [],
            }
            result = c._parse_event(event)
            assert result is not None
            assert result["type"] == "AWS_LOGGING_DISABLED"
            assert result["risk"] == "CRITICAL"
