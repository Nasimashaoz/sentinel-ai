# Sentinel AI — Architecture Deep Dive

## Design Philosophy

Sentinel AI is designed around three principles:

1. **Zero cloud dependency** — all processing happens on your server
2. **Graceful degradation** — works without Claude API key using rule-based analysis
3. **Minimal footprint** — reads logs passively, no kernel modules, no agents

## Data Flow

```
Linux System Logs
      │
      ▼
┌─────────────────┐
│  LogCollector   │  Reads: auth.log, nginx/access.log, ps aux, ss -tn
│  (async, 10s)   │  State: tail position, failed login counters
└────────┬────────┘
         │  List[event_dict]
         ▼
┌─────────────────┐
│ ThreatAnalyzer  │  1. Rule-based pre-filter (fast, no API)
│                 │  2. Claude AI enrichment (if API key set)
│                 │  Output: enriched threat dict or None
└────────┬────────┘
         │  threat_dict
         ▼
┌─────────────────┐
│   RiskScorer    │  Numeric score 0-100
│                 │  Factors: risk level + event volume
└────────┬────────┘
         │  scored threat
         ▼
┌─────────────────────────────────────┐
│          Alert Deduplication        │
│  Cooldown per (threat_type, src_ip) │
└────────┬────────────────────────────┘
         │  if should_alert
         ▼
┌──────────────────────────────────────────────┐
│              Alert Engine                    │
│  Telegram │ Slack │ WhatsApp │ Email         │
│  (async gather — all channels in parallel)   │
└──────────────────────────────────────────────┘
         │
         ▼
┌─────────────────┐
│ ReportGenerator │  Persists to data/incidents.json
│                 │  Serves HTML/JSON reports on demand
└─────────────────┘
```

## Concurrency Model

- Single `asyncio` event loop
- `LogCollector.collect()` is `async` — non-blocking I/O
- `ThreatAnalyzer._claude_analyze()` uses `loop.run_in_executor` to wrap the sync Anthropic SDK
- Alert channels use `asyncio.gather` — all channels notified in parallel
- Dashboard uses Flask (separate process via `docker-compose`)

## Adding a New Collector

```python
# In core/collector.py, add a new method:
async def _collect_docker_events(self) -> list:
    events = []
    # Parse: docker events --since 10s --format json
    result = subprocess.run(['docker', 'events', '--since', '10s',
                             '--format', '{{json .}}', '--filter', 'event=exec_start'],
                            capture_output=True, text=True, timeout=12)
    for line in result.stdout.splitlines():
        import json
        evt = json.loads(line)
        if 'exec_start' in evt.get('Action', ''):
            events.append({
                'type': 'DOCKER_EXEC',
                'source_ip': 'localhost',
                'process': evt.get('Actor', {}).get('Attributes', {}).get('execID', ''),
                'raw': line,
            })
    return events
```

Then add it to `collect()`:
```python
events.extend(await self._collect_docker_events())
```

## Adding a New Alert Channel

```python
# alerts/discord_alert.py
class DiscordAlerter:
    def __init__(self):
        self.webhook = os.getenv("DISCORD_WEBHOOK_URL")

    async def send(self, threat: dict):
        # Build Discord embed payload and POST to webhook
        ...
```

Then register in `sentinel.py`:
```python
if os.getenv("DISCORD_WEBHOOK_URL"):
    from alerts.discord_alert import DiscordAlerter
    alerters.append(DiscordAlerter())
```

That's all it takes — the agent loop handles the rest automatically.
