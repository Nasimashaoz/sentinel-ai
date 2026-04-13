# Sentinel AI — GCP Audit Log Monitoring

Detect suspicious Google Cloud activity: IAM changes, firewall modifications, storage ACL changes, logging disabled, unexpected VM launches.

## Requirements

```bash
pip install google-cloud-logging google-auth
```

## Enable in `.env`

```env
GCP_ENABLED=true
GCP_PROJECT_ID=your-project-id
GCP_LOOKBACK_MINUTES=5

# Option A: Service account key file
GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json

# Option B: gcloud ADC (local dev)
# gcloud auth application-default login
```

## IAM Permissions Required

```bash
# Grant the service account log viewer
gcloud projects add-iam-policy-binding YOUR_PROJECT \
  --member="serviceAccount:sentinel-ai@YOUR_PROJECT.iam.gserviceaccount.com" \
  --role="roles/logging.viewer"
```

## What Gets Detected

| Event | Type | Risk |
|---|---|---|
| Audit log deleted/disabled | `GCP_LOGGING_DISABLED` | CRITICAL |
| IAM policy changed | `GCP_SUSPICIOUS_API` | HIGH |
| Service account key created | `GCP_SUSPICIOUS_API` | HIGH |
| Firewall rule modified | `GCP_SUSPICIOUS_API` | HIGH |
| Storage bucket ACL changed | `GCP_SUSPICIOUS_API` | HIGH |
| Unexpected VM created | `GCP_SUSPICIOUS_API` | MEDIUM |
