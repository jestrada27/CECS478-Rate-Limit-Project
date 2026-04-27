"""
Generates summary CSV and a simple ASCII chart from logs.csv.
Run after make demo to produce evaluation artifacts.
"""

import csv
import json
import os
from collections import Counter, defaultdict
from datetime import datetime

LOG_CSV = os.environ.get("LOG_CSV", "logs.csv")
OUT_DIR = "artifacts/release"
os.makedirs(OUT_DIR, exist_ok=True)


def load_logs() -> list[dict]:
    if not os.path.exists(LOG_CSV):
        print(f"[export] {LOG_CSV} not found — run make demo first.")
        return []
    with open(LOG_CSV, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def write_summary_csv(rows: list[dict]) -> None:
    counter = Counter(r["status"] for r in rows)
    ip_counts = Counter(r["client_ip"] for r in rows)
    out_path = os.path.join(OUT_DIR, "metrics_summary.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["metric", "value"])
        w.writerow(["total_requests", len(rows)])
        for status, count in sorted(counter.items()):
            w.writerow([f"status_{status}", count])
        w.writerow(["unique_clients", len(ip_counts)])
    print(f"[export] Wrote {out_path}")


def write_per_ip_csv(rows: list[dict]) -> None:
    by_ip: dict[str, dict] = defaultdict(lambda: Counter())
    for r in rows:
        by_ip[r["client_ip"]][r["status"]] += 1
    out_path = os.path.join(OUT_DIR, "per_ip_stats.csv")
    with open(out_path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["client_ip", "allowed", "suspicious", "blocked", "total"])
        for ip, counts in sorted(by_ip.items()):
            a = counts.get("allowed", 0)
            s = counts.get("suspicious", 0)
            b = counts.get("blocked", 0)
            w.writerow([ip, a, s, b, a + s + b])
    print(f"[export] Wrote {out_path}")


def print_ascii_chart(rows: list[dict]) -> None:
    counter = Counter(r["status"] for r in rows)
    total = sum(counter.values()) or 1
    print("\n── Request Status Distribution ───────────────────")
    for status in ("allowed", "suspicious", "blocked"):
        count = counter.get(status, 0)
        bar = "█" * int(40 * count / total)
        print(f"  {status:12s} │{bar:<40}│ {count:4d} ({100*count/total:.1f}%)")
    print("──────────────────────────────────────────────────\n")


def main() -> None:
    rows = load_logs()
    if not rows:
        return
    write_summary_csv(rows)
    write_per_ip_csv(rows)
    print_ascii_chart(rows)
    print(f"[export] Done. Total log rows processed: {len(rows)}")


if __name__ == "__main__":
    main()
