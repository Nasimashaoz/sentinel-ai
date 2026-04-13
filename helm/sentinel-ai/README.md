# Sentinel AI — Helm Chart

Deploy Sentinel AI to Kubernetes in 60 seconds.

## Install

```bash
# Clone the repo
git clone https://github.com/Nasimashaoz/sentinel-ai
cd sentinel-ai

# Basic install (Kubernetes monitoring only, no API keys)
helm install sentinel-ai ./helm/sentinel-ai \
  --namespace monitoring --create-namespace

# With Telegram + Claude AI
helm install sentinel-ai ./helm/sentinel-ai \
  --namespace monitoring --create-namespace \
  --set ai.claude.apiKey=YOUR_KEY \
  --set alerts.telegram.enabled=true \
  --set alerts.telegram.botToken=YOUR_BOT_TOKEN \
  --set alerts.telegram.chatId=YOUR_CHAT_ID

# With Ollama (offline AI, no API key)
helm install sentinel-ai ./helm/sentinel-ai \
  --namespace monitoring --create-namespace \
  --set ai.claude.enabled=false \
  --set ai.ollama.enabled=true

# With PagerDuty for production on-call
helm install sentinel-ai ./helm/sentinel-ai \
  --namespace monitoring --create-namespace \
  --set alerts.pagerduty.enabled=true \
  --set alerts.pagerduty.routingKey=YOUR_ROUTING_KEY
```

## Check Status

```bash
kubectl get pods -n monitoring
kubectl logs -n monitoring deployment/sentinel-ai -f
kubectl port-forward -n monitoring svc/sentinel-ai 8080:8080
# Open http://localhost:8080
```

## Values Reference

See [values.yaml](values.yaml) for all configurable options.

## Upgrade

```bash
helm upgrade sentinel-ai ./helm/sentinel-ai --namespace monitoring
```

## Uninstall

```bash
helm uninstall sentinel-ai --namespace monitoring
```
