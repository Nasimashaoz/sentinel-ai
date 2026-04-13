# Sentinel AI — Auto-Remediation Engine

Sentinel AI can automatically execute remediation actions when threats are detected.

## ⚠️ Safety First

Auto-remediation is **disabled by default**. It runs in **dry-run mode** until you explicitly enable it.

```env
# Default: dry run (logs what WOULD happen, never executes)
AUTO_REMEDIATE=false

# Enable auto-remediation for safe actions
AUTO_REMEDIATE=true

# Also allow auto-remediation for CRITICAL threats
AUTO_REMEDIATE_CRITICAL=true
```

## Safety Model

| Layer | Protection |
|---|---|
| **Whitelist-only** | Only pre-approved commands from the playbook are ever run |
| **Dry-run default** | Nothing executes unless you set `AUTO_REMEDIATE=true` |
| **Safe flag** | Each playbook entry has `safe_for_auto: true/false` |
| **CRITICAL gate** | CRITICAL-risk actions require `AUTO_REMEDIATE_CRITICAL=true` |
| **Audit log** | Every action (including dry runs) logged to `data/remediation_audit.jsonl` |
| **Rollback stored** | Every action stores the undo command |

## Playbook

| Threat | Action | Safe for auto? |
|---|---|---|
| `BRUTE_FORCE` | `fail2ban-client set sshd banip <ip>` | ✅ Yes |
| `PORT_SCAN` | `iptables -A INPUT -s <ip> -j DROP` | ✅ Yes |
| `WEB_SCAN` | `iptables -A INPUT -s <ip> -j DROP` | ✅ Yes |
| `SUSPICIOUS_PROCESS` | `kill -9 <pid>` | ❌ Manual only |
| `K8S_PRIVILEGED_CONTAINER` | `kubectl delete pod` | ❌ Manual only |
| `AWS_ROOT_USAGE` | Alert only | ❌ Cannot auto-block |

## Audit Log

Every action is appended to `data/remediation_audit.jsonl`:
```json
{
  "ts": "2026-04-13T18:30:42",
  "threat_type": "BRUTE_FORCE",
  "risk": "CRITICAL",
  "source_ip": "45.33.32.156",
  "command": "fail2ban-client set sshd banip 45.33.32.156",
  "rollback": "fail2ban-client set sshd unbanip 45.33.32.156",
  "result": {"action": "executed", "success": true}
}
```

## Rollback

```bash
# View all auto-remediation actions
cat data/remediation_audit.jsonl | python -m json.tool

# Manually rollback a ban
fail2ban-client set sshd unbanip 45.33.32.156
iptables -D INPUT -s 45.33.32.156 -j DROP
```
