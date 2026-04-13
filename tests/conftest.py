import pytest
import os

# Ensure tests always run in test mode (no real API calls)
os.environ.setdefault("SENTINEL_TEST_MODE", "true")
os.environ.setdefault("AUTO_REMEDIATE", "false")
os.environ.setdefault("K8S_ENABLED", "false")
os.environ.setdefault("AWS_ENABLED", "false")
os.environ.setdefault("GCP_ENABLED", "false")
os.environ.setdefault("AZURE_ENABLED", "false")
