# Sentinel AI — Azure Activity Log Monitoring

Detect suspicious Azure activity: role assignments, service principal creation, Key Vault access, NSG modifications, diagnostic settings deleted.

## Requirements

```bash
pip install azure-identity azure-mgmt-monitor
```

## Enable in `.env`

```env
AZURE_ENABLED=true
AZURE_SUBSCRIPTION_ID=your-subscription-id
AZURE_LOOKBACK_MINUTES=5

# Option A: Service principal
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=your-client-id
AZURE_CLIENT_SECRET=your-client-secret

# Option B: Azure CLI (local dev)
# az login
```

## Required Azure Role

```bash
# Assign Monitoring Reader to your service principal
az role assignment create \
  --assignee YOUR_CLIENT_ID \
  --role "Monitoring Reader" \
  --scope /subscriptions/YOUR_SUBSCRIPTION_ID
```

## What Gets Detected

| Event | Type | Risk |
|---|---|---|
| Diagnostic settings deleted | `AZURE_LOGGING_DISABLED` | CRITICAL |
| Azure AD sign-in failure | `AZURE_SIGNIN_FAILURE` | HIGH |
| Role assignment created | `AZURE_SUSPICIOUS_OPERATION` | HIGH |
| Service principal created | `AZURE_SUSPICIOUS_OPERATION` | HIGH |
| Key Vault secret read | `AZURE_SUSPICIOUS_OPERATION` | HIGH |
| NSG rule modified | `AZURE_SUSPICIOUS_OPERATION` | HIGH |
| Resource deployment | `AZURE_SUSPICIOUS_OPERATION` | MEDIUM |
