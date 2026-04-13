# Sentinel AI — Multi-Server Mesh

Monitor all your servers from one place. One coordinator, unlimited nodes.

## Architecture

```
 Server 1 (node)          Server 2 (node)          Server 3 (node)
 ┌───────────────┐        ┌───────────────┐        ┌───────────────┐
 │ Sentinel AI   │        │ Sentinel AI   │        │ Sentinel AI   │
 │ sentinel.py   │        │ sentinel.py   │        │ sentinel.py   │
 │ MeshNode      │        │ MeshNode      │        │ MeshNode      │
 └───────┬───────┘        └───────┬───────┘        └───────┬───────┘
         │  push threats          │  heartbeat             │  pull blocklist
         └────────────────────────┼────────────────────────┘
                                  ▼
                    ┌─────────────────────────┐
                    │  Coordinator Server      │
                    │  mesh/coordinator.py     │
                    │  :8888                   │
                    └─────────────────────────┘
```

## Setup (10 minutes)

### On the Coordinator Server

```bash
git clone https://github.com/Nasimashaoz/sentinel-ai
cd sentinel-ai
pip install -r requirements.txt

export MESH_NODE_SECRET=your_strong_secret_here
export MESH_COORDINATOR_PORT=8888
python -m mesh.coordinator
```

### On Each Node Server

Add to `.env`:
```env
MESH_COORDINATOR_URL=http://YOUR_COORDINATOR_IP:8888
MESH_NODE_SECRET=your_strong_secret_here
SENTINEL_SERVER_NAME=web-server-01    # unique name per server
```

That's it — run `python sentinel.py` as normal.

## What the Mesh Does

| Feature | Description |
|---|---|
| **Threat sync** | Every threat detected on any node is pushed to the coordinator |
| **Auto-blocklist** | IPs seen attacking 5+ servers are auto-added to the global blocklist |
| **Blocklist pull** | Each node pulls the global blocklist every 5 mins |
| **Heartbeat** | Nodes ping the coordinator every 60s — see which servers are online |
| **Cross-server view** | `/api/summary` gives a unified threat picture across all servers |

## API Reference

```bash
# Check all nodes
curl -H "X-Sentinel-Secret: your_secret" http://coordinator:8888/api/nodes

# Get cross-server summary
curl -H "X-Sentinel-Secret: your_secret" http://coordinator:8888/api/summary

# Get global blocklist
curl -H "X-Sentinel-Secret: your_secret" http://coordinator:8888/api/blocklist
```
