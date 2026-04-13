"""
Sentinel AI — Real-time Web Dashboard
Flask-based live threat feed, incident timeline, and risk heatmap.
"""

import json
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path
from flask import Flask, render_template, jsonify, Response
import threading
import time

# Allow imports from project root
sys.path.insert(0, str(Path(__file__).parent.parent))

app = Flask(__name__)
app.secret_key = os.getenv("DASHBOARD_SECRET", "sentinel-dev-secret")

# In-memory store shared with agent via file
DATA_FILE = Path("data/incidents.json")


def load_incidents():
    if DATA_FILE.exists():
        try:
            return json.loads(DATA_FILE.read_text())
        except Exception:
            return []
    return []


@app.route("/")
def index():
    incidents = load_incidents()
    stats = {
        "total": len(incidents),
        "critical": sum(1 for i in incidents if i.get("risk") == "CRITICAL"),
        "high": sum(1 for i in incidents if i.get("risk") == "HIGH"),
        "medium": sum(1 for i in incidents if i.get("risk") == "MEDIUM"),
        "low": sum(1 for i in incidents if i.get("risk") == "LOW"),
    }
    recent = sorted(incidents, key=lambda x: x.get("timestamp", ""), reverse=True)[:20]
    return render_template("index.html", stats=stats, incidents=recent)


@app.route("/api/incidents")
def api_incidents():
    return jsonify(load_incidents())


@app.route("/api/stats")
def api_stats():
    incidents = load_incidents()
    now = datetime.utcnow()
    last_24h = [i for i in incidents if _within_hours(i.get("timestamp", ""), 24)]
    return jsonify({
        "total_all_time": len(incidents),
        "last_24h": len(last_24h),
        "by_risk": {
            "CRITICAL": sum(1 for i in incidents if i.get("risk") == "CRITICAL"),
            "HIGH": sum(1 for i in incidents if i.get("risk") == "HIGH"),
            "MEDIUM": sum(1 for i in incidents if i.get("risk") == "MEDIUM"),
            "LOW": sum(1 for i in incidents if i.get("risk") == "LOW"),
        },
        "by_type": _count_by(incidents, "type"),
        "top_ips": _top_ips(incidents),
    })


@app.route("/stream")
def stream():
    """Server-Sent Events endpoint for live threat feed."""
    def event_stream():
        last_count = 0
        while True:
            incidents = load_incidents()
            if len(incidents) != last_count:
                new = sorted(incidents, key=lambda x: x.get("timestamp", ""), reverse=True)
                data = json.dumps(new[:5])
                yield f"data: {data}\n\n"
                last_count = len(incidents)
            time.sleep(5)
    return Response(event_stream(), mimetype="text/event-stream")


def _within_hours(ts_str, hours):
    try:
        ts = datetime.fromisoformat(ts_str)
        return datetime.utcnow() - ts < timedelta(hours=hours)
    except Exception:
        return False


def _count_by(incidents, field):
    counts = {}
    for i in incidents:
        key = i.get(field, "UNKNOWN")
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))


def _top_ips(incidents, n=10):
    counts = {}
    for i in incidents:
        ip = i.get("source_ip", "unknown")
        counts[ip] = counts.get(ip, 0) + 1
    return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n])


if __name__ == "__main__":
    port = int(os.getenv("DASHBOARD_PORT", 8080))
    app.run(host="0.0.0.0", port=port, debug=False)
