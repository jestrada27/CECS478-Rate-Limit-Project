from flask import Flask, jsonify, request
from datetime import datetime, timezone
from collections import defaultdict
import csv
import json
import os
import time
import hashlib
import hmac

app = Flask(__name__)

# Configuration 
REQUEST_LIMIT = 20          # max requests per window per IP
WINDOW_SECONDS = 60         # sliding window duration in seconds
ALERT_THRESHOLD = 15        # flag as suspicious at this count (before block)
LOG_SECRET = os.environ.get("LOG_SECRET", "changeme-in-production")

# In-memory state
request_windows: dict[str, list] = defaultdict(list)
stats = {
    "total_allowed": 0,
    "total_blocked": 0,
    "total_suspicious": 0,
    "start_time": datetime.now(timezone.utc).isoformat(),
}

# Log files
LOG_DIR = os.environ.get("LOG_DIR", ".")
CSV_LOG = os.path.join(LOG_DIR, "logs.csv")
ALERT_LOG = os.path.join(LOG_DIR, "alerts.json")


def _hmac_row(fields: list[str]) -> str:
    """Produce a short HMAC so log rows are tamper-evident."""
    msg = "|".join(str(f) for f in fields).encode()
    return hmac.new(LOG_SECRET.encode(), msg, hashlib.sha256).hexdigest()[:16]


def append_csv_log(client_ip: str, path: str, status: str, count: int) -> None:
    file_exists = os.path.exists(CSV_LOG)
    ts = datetime.now(timezone.utc).isoformat()
    row = [ts, client_ip, path, status, count]
    mac = _hmac_row(row)
    row.append(mac)
    with open(CSV_LOG, "a", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        if not file_exists:
            writer.writerow(["timestamp", "client_ip", "path", "status", "window_count", "hmac"])
        writer.writerow(row)


def append_alert(client_ip: str, path: str, count: int) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    entry = {
        "timestamp": ts,
        "client_ip": client_ip,
        "path": path,
        "window_count": count,
        "level": "ALERT",
    }
    with open(ALERT_LOG, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry) + "\n")


# Sliding-window rate limiter 

def _prune_window(ip: str) -> None:
    """Remove timestamps outside the current window."""
    cutoff = time.time() - WINDOW_SECONDS
    request_windows[ip] = [(t, p) for t, p in request_windows[ip] if t >= cutoff]


def check_rate_limit(ip: str, path: str) -> tuple[bool, int]:
    """
    Returns (blocked: bool, window_count: int).
    Adds the current request to the window first, then checks.
    """
    now = time.time()
    _prune_window(ip)
    request_windows[ip].append((now, path))
    count = len(request_windows[ip])
    blocked = count > REQUEST_LIMIT
    return blocked, count


# Middleware 

@app.before_request
def monitor_requests():
    # Skip internal Flask endpoints
    if request.path in ("/favicon.ico",):
        return None

    client_ip = request.headers.get("X-Forwarded-For", request.remote_addr) or "unknown"
    # Only take the first IP if comma-separated list (proxy chain)
    client_ip = client_ip.split(",")[0].strip()

    blocked, count = check_rate_limit(client_ip, request.path)

    if blocked:
        stats["total_blocked"] += 1
        append_csv_log(client_ip, request.path, "blocked", count)
        append_alert(client_ip, request.path, count)
        return (
            jsonify(
                {
                    "message": "Too many requests. Rate limit exceeded.",
                    "status": "blocked",
                    "retry_after_seconds": WINDOW_SECONDS,
                }
            ),
            429,
        )

    if count >= ALERT_THRESHOLD:
        stats["total_suspicious"] += 1
        append_csv_log(client_ip, request.path, "suspicious", count)
        append_alert(client_ip, request.path, count)
    else:
        append_csv_log(client_ip, request.path, "allowed", count)

    stats["total_allowed"] += 1
    return None


# Routes 

@app.route("/")
def home():
    return jsonify({"message": "HTTP monitoring server is running", "status": "ok"})


@app.route("/health")
def health():
    return jsonify({"status": "ok", "uptime_start": stats["start_time"]})


@app.route("/metrics")
def metrics():
    """Export current runtime stats as JSON (satisfies observability requirement)."""
    return jsonify(
        {
            "total_allowed": stats["total_allowed"],
            "total_blocked": stats["total_blocked"],
            "total_suspicious": stats["total_suspicious"],
            "active_clients": len(request_windows),
            "uptime_start": stats["start_time"],
        }
    )


@app.route("/metrics/csv")
def metrics_csv():
    """Export metrics as CSV text."""
    lines = [
        "metric,value",
        f"total_allowed,{stats['total_allowed']}",
        f"total_blocked,{stats['total_blocked']}",
        f"total_suspicious,{stats['total_suspicious']}",
        f"active_clients,{len(request_windows)}",
    ]
    return "\n".join(lines), 200, {"Content-Type": "text/csv"}


@app.route("/data")
def data():
    return jsonify({"payload": "some sensitive server data", "status": "ok"})


# Entry point 

if __name__ == "__main__":
    # Non-debug in production; debug=True only for dev convenience
    debug = os.environ.get("FLASK_ENV", "production") == "development"
    app.run(host="0.0.0.0", port=5000, debug=debug)
