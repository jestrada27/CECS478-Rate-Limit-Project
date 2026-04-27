"""
Traffic simulation script for the HTTP Request Monitoring system.
Sends both normal and attack traffic to demonstrate rate limiting.
"""

import requests
import time
import sys
import json
from datetime import datetime

BASE_URL = "http://localhost:5000"


def send_normal_traffic(n: int = 10, delay: float = 0.3) -> dict:
    """Simulate a legitimate user making spaced-out requests."""
    print(f"\n[Normal Traffic] Sending {n} requests with {delay}s delay...")
    results = {"allowed": 0, "blocked": 0, "suspicious": 0}
    for i in range(n):
        try:
            resp = requests.get(f"{BASE_URL}/", timeout=5)
            status = resp.status_code
            body = resp.json()
            label = body.get("status", "ok")
            if status == 429:
                results["blocked"] += 1
                label = "BLOCKED"
            elif status == 200:
                results["allowed"] += 1
            print(f"  Request {i+1:3d}: HTTP {status} → {label}")
        except requests.exceptions.ConnectionError:
            print(f"  Request {i+1:3d}: CONNECTION REFUSED — is the server up?")
            sys.exit(1)
        time.sleep(delay)
    return results


def send_attack_traffic(n: int = 30, delay: float = 0.0) -> dict:
    """Simulate a bot flooding the server with rapid requests."""
    print(f"\n[Attack Traffic] Sending {n} rapid requests (no delay)...")
    results = {"allowed": 0, "blocked": 0}
    for i in range(n):
        try:
            resp = requests.get(f"{BASE_URL}/data", timeout=5)
            if resp.status_code == 429:
                results["blocked"] += 1
                status_label = "BLOCKED (429)"
            else:
                results["allowed"] += 1
                status_label = f"allowed ({resp.status_code})"
            print(f"  Request {i+1:3d}: {status_label}")
        except requests.exceptions.ConnectionError:
            print(f"  Request {i+1:3d}: CONNECTION REFUSED — is the server up?")
            sys.exit(1)
        if delay:
            time.sleep(delay)
    return results


def fetch_metrics() -> dict:
    """Pull the /metrics endpoint and display current counters."""
    try:
        resp = requests.get(f"{BASE_URL}/metrics", timeout=5)
        return resp.json()
    except Exception as e:
        print(f"[Metrics] Could not fetch: {e}")
        return {}


def save_summary(normal: dict, attack: dict, metrics: dict) -> None:
    ts = datetime.utcnow().isoformat()
    summary = {
        "timestamp": ts,
        "normal_traffic": normal,
        "attack_traffic": attack,
        "server_metrics": metrics,
    }
    with open("artifacts/release/demo_summary.json", "w") as fh:
        json.dump(summary, fh, indent=2)
    print("\n[Summary] Saved to artifacts/release/demo_summary.json")


def main() -> None:
    print("=" * 55)
    print("  HTTP Monitoring & Rate Limiting — Demo")
    print("=" * 55)

    # Phase 1: normal user traffic (should all be allowed)
    normal_results = send_normal_traffic(n=10, delay=0.1)
    print(f"  → Allowed: {normal_results['allowed']}  Blocked: {normal_results['blocked']}")

    # Brief pause before attack phase
    time.sleep(1)

    # Phase 2: flood attack (should trigger rate limit)
    attack_results = send_attack_traffic(n=30)
    print(f"  → Allowed: {attack_results['allowed']}  Blocked: {attack_results['blocked']}")

    # Phase 3: pull metrics
    print("\n[Metrics] Current server counters:")
    metrics = fetch_metrics()
    for k, v in metrics.items():
        print(f"  {k}: {v}")

    # Phase 4: save summary artifact
    save_summary(normal_results, attack_results, metrics)

    # Exit code 0 only if blocking actually occurred
    if attack_results["blocked"] == 0:
        print("\n[WARN] No requests were blocked — check server state or threshold config.")
        sys.exit(1)
    print("\n[OK] Demo complete. Rate limiting is working correctly.")


if __name__ == "__main__":
    main()
