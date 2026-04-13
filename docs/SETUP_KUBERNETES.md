# Sentinel AI — Kubernetes Monitoring

Monitor your Kubernetes cluster for security events: pod crashes, RBAC violations, privileged containers, and image pull failures.

## Requirements

```bash
pip install kubernetes
```

## Enable in `.env`

```env
K8S_ENABLED=true
K8S_NAMESPACE=        # empty = all namespaces, or specify e.g. "production"
```

## Auth

**Inside a Kubernetes pod** (recommended for production):
- Sentinel AI auto-detects in-cluster config via service account
- Give it a read-only ClusterRole:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: sentinel-ai-reader
rules:
- apiGroups: [""]
  resources: ["pods", "events"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: sentinel-ai-reader-binding
subjects:
- kind: ServiceAccount
  name: sentinel-ai
  namespace: monitoring
roleRef:
  kind: ClusterRole
  name: sentinel-ai-reader
  apiGroup: rbac.authorization.k8s.io
```

**Outside cluster** (local dev):
- Uses `~/.kube/config` automatically

## What Gets Detected

| Event | Type | Risk |
|---|---|---|
| Pod crash / OOMKilled | `K8S_POD_CRASH` | HIGH |
| Image pull failure | `K8S_IMAGE_PULL_FAILURE` | MEDIUM |
| RBAC Forbidden API call | `K8S_RBAC_VIOLATION` | HIGH |
| Privileged pod (hostPID/hostNetwork) | `K8S_PRIVILEGED_POD` | CRITICAL |
| Privileged container (`securityContext.privileged`) | `K8S_PRIVILEGED_CONTAINER` | CRITICAL |
