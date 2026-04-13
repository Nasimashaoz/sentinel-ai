# Sentinel AI — Helm Deployment Guide

Deploy to any Kubernetes cluster (EKS, GKE, AKS, k3s, minikube) in 60 seconds.

## Prerequisites

- Kubernetes 1.24+
- Helm 3.10+
- kubectl configured

## Quick Install

```bash
git clone https://github.com/Nasimashaoz/sentinel-ai
cd sentinel-ai

helm install sentinel-ai ./helm/sentinel-ai \
  --namespace monitoring \
  --create-namespace
```

## Production Install (all features)

```bash
helm install sentinel-ai ./helm/sentinel-ai \
  --namespace monitoring --create-namespace \
  --set ai.claude.apiKey=$CLAUDE_API_KEY \
  --set alerts.telegram.enabled=true \
  --set alerts.telegram.botToken=$TELEGRAM_BOT_TOKEN \
  --set alerts.telegram.chatId=$TELEGRAM_CHAT_ID \
  --set alerts.pagerduty.enabled=true \
  --set alerts.pagerduty.routingKey=$PD_ROUTING_KEY \
  --set prometheus.serviceMonitor.enabled=true \
  --set kubernetes.enabled=true
```

## What Gets Created

| Resource | Purpose |
|---|---|
| `Deployment` | Sentinel AI agent pod |
| `ServiceAccount` | Identity for k8s API access |
| `ClusterRole` | Read-only access to pods/events |
| `ClusterRoleBinding` | Binds role to service account |
| `Service` | Exposes dashboard (:8080) + metrics (:9090) |
| `PersistentVolumeClaim` | Stores incident data (1Gi) |
| `ServiceMonitor` | Prometheus Operator integration (optional) |

## Verify

```bash
# Check pod is running
kubectl get pods -n monitoring -l app.kubernetes.io/name=sentinel-ai

# Stream logs
kubectl logs -n monitoring deployment/sentinel-ai -f

# Access dashboard
kubectl port-forward -n monitoring svc/sentinel-ai 8080:8080
open http://localhost:8080

# Check metrics
kubectl port-forward -n monitoring svc/sentinel-ai 9090:9090
curl http://localhost:9090/metrics
```

## Cloud-Specific Notes

### EKS (AWS)
```bash
# Use IRSA for AWS credentials (no static keys)
helm install sentinel-ai ./helm/sentinel-ai \
  --set collectors.aws.enabled=true \
  --set collectors.aws.region=us-east-1
# Annotate the ServiceAccount with your IAM role ARN
```

### GKE (Google Cloud)
```bash
# Use Workload Identity
helm install sentinel-ai ./helm/sentinel-ai \
  --set collectors.gcp.enabled=true \
  --set collectors.gcp.projectId=your-project
```

### AKS (Azure)
```bash
# Use Azure Managed Identity
helm install sentinel-ai ./helm/sentinel-ai \
  --set collectors.azure.enabled=true \
  --set collectors.azure.subscriptionId=your-sub-id
```
