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
        with patch.dict(os.environ, {"K8S_ENABLED": "false"}):
            from core.collectors.kubernetes_collector import KubernetesCollector
            c = KubernetesCollector()
            mock_event = MagicMock()
            mock_event.reason = "OOMKilling"
            mock_event.message = "Memory limit exceeded for container app"
            mock_event.involved_object.name = "my-pod-abc123"
            mock_event.involved_object.namespace = "production"
            mock_event.last_timestamp = None
            mock_event.event_time = None
            result = c._parse_event(mock_event)
            assert result is not None
            assert result["type"] == "K8S_OOM_KILLED"
            assert "my-pod" in result["raw"]

    def test_parse_image_pull_backoff(self):
        from unittest.mock import patch, MagicMock
        with patch.dict(os.environ, {"K8S_ENABLED": "false"}):
            from core.collectors.kubernetes_collector import KubernetesCollector
            c = KubernetesCollector()
            mock_event = MagicMock()
            mock_event.reason = "BackOff"
            mock_event.message = "Back-off pulling image \"private.registry/app:latest\""
            mock_event.involved_object.name = "my-deployment-xyz"
            mock_event.involved_object.namespace = "default"
            mock_event.last_timestamp = None
            mock_event.event_time = None
            result = c._parse_event(mock_event)
            assert result is not None
            assert result["type"] == "K8S_IMAGE_PULL_BACKOFF"


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
                "eventName": "ConsoleLogin",
                "userIdentity": {"type": "Root", "arn": "arn:aws:iam::123:root"},
                "sourceIPAddress": "1.2.3.4",
                "eventTime": "2026-04-13T08:00:00Z",
                "requestParameters": None,
            }
            result = c._parse_event(event)
            assert result is not None
            assert result["type"] == "AWS_ROOT_LOGIN"
            assert result["risk"] == "CRITICAL"

    def test_parse_cloudtrail_disabled(self):
        from unittest.mock import patch
        with patch.dict(os.environ, {"AWS_ENABLED": "false"}):
            from core.collectors.aws_collector import AWSCollector
            c = AWSCollector()
            event = {
                "eventName": "StopLogging",
                "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::123:user/hacker"},
                "sourceIPAddress": "5.6.7.8",
                "eventTime": "2026-04-13T08:00:00Z",
                "requestParameters": None,
            }
            result = c._parse_event(event)
            assert result is not None
            assert result["type"] == "AWS_CLOUDTRAIL_DISABLED"
            assert result["risk"] == "CRITICAL"
