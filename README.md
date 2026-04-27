# HTTP Request Monitoring and Rate-Limiting Defense System

![CI](https://github.com/<your-username>/http-request-monitoring-rate-limit/actions/workflows/ci.yml/badge.svg)
![Coverage](https://img.shields.io/badge/coverage-97%25-brightgreen)

**CECS 478 — Security Project | Alpha-Beta Integrated Release**

---

## What Works / What's Next

### What Works
- Flask server with `/`, `/health`, `/data`, `/metrics`, `/metrics/csv` endpoints
- Sliding-window rate limiter (configurable limit + window duration)
- Two-tier detection: **suspicious** flag before hard **block**
- `X-Forwarded-For` header support for correct IP tracking behind proxies
- Tamper-evident CSV logs (HMAC appended to each row)
- JSON alert log (`alerts.json`) for all suspicious and blocked events
- `/metrics` and `/metrics/csv` endpoints for live observability
- 12 automated tests (2 Alpha + 10 Beta) with 97% code coverage
- CI pipeline (GitHub Actions): build → test → coverage check → Docker build
- Least-privilege Docker: non-root user, `no-new-privileges` security option
- `make up && make demo` single-command vertical slice

### What's Next 
- PCAP capture with `tcpdump` during the demo run
- Response-time charts under concurrent load
- Final evaluation: precision/recall of suspicious-flag classifier
- Persistent request counter reset (currently in-memory, resets on container restart)
- Optional: Redis-backed counters for multi-container deployment

---

## Problem Statement

Web applications are common targets for DoS-style attacks involving high request volume from automated bots. This system monitors incoming HTTP requests, detects suspicious frequency patterns per client, and applies sliding-window rate limiting to defend server availability.

---

## Architecture

```
Normal Client          Attack Script
(Legitimate User)      (Spam Requests)
       │                     │
       └──────────┬──────────┘
                  ▼
         Flask Web Server
         (HTTP Endpoints)
                  │
                  ▼
        Request Monitoring
        (Sliding Window per IP)
                  │
          ┌───────┴───────┐
          ▼               ▼
    Below threshold   Above threshold
          │               │
          ▼               ▼
     allowed         suspicious / blocked
          │               │
          └───────┬───────┘
                  ▼
           Logs (CSV + JSON)
           Metrics (JSON/CSV endpoints)
```

### Components

| Component | File | Responsibility |
|---|---|---|
| Flask app | `app/main.py` | HTTP routing, middleware |
| Rate limiter | `app/main.py` | Sliding-window counter per IP |
| Logger | `app/main.py` | CSV + JSONL log writes |
| Attack sim | `scripts/attack_sim.py` | Traffic generation |
| Metrics export | `scripts/export_metrics.py` | Artifact generation |
| Tests | `tests/test_main.py` | 12-test suite |

---

## Security Invariants

1. **Plaintext never written to disk** — logs contain only timestamps, IPs, paths, status, and request counts. No request bodies or headers are stored.
2. **Tamper-evident logs** — every CSV row includes a 16-character HMAC derived from `LOG_SECRET`. Any modification to a row changes its HMAC, making tampering detectable.
3. **Least-privilege execution** — Docker container runs as `appuser` (non-root). The `no-new-privileges` security option prevents privilege escalation.
4. **Input validation** — client IP is extracted from `X-Forwarded-For` or `remote_addr`, with comma-split handling for proxy chains. No user input is executed or interpolated into queries.
5. **Rate limiting applied before route handlers** — the `@app.before_request` hook intercepts and short-circuits blocked requests before any business logic runs.

---

## Repository Structure

```
.
├── app/
│   └── main.py                  # Flask app, rate limiter, logging
├── scripts/
│   ├── attack_sim.py            # Traffic simulation demo
│   └── export_metrics.py        # Artifact export script
├── tests/
│   └── test_main.py             # 12-test suite (Alpha + Beta)
├── artifacts/
│   └── release/                 # Evidence artifacts
│       ├── logs.csv             # Sample log output
│       ├── per_ip_stats.csv     # Per-client breakdown
│       ├── metrics_summary.json # Aggregated counters
│       └── draft_results.md     # Evaluation in progress
├── docs/
│   └── architecture_diagram.png
├── .github/
│   └── workflows/ci.yml         # CI: build, test, coverage
├── Dockerfile
├── docker-compose.yml
├── Makefile
├── requirements.txt
├── pyproject.toml
└── README.md
```

---

## Runbook

### Prerequisites

- Docker + Docker Compose
- Python 3.11+
- GNU Make

### Quick Start (fresh clone)

```bash
# 1. Clone and enter the repo
git clone <repo-url>
cd http-request-monitoring-rate-limit

# 2. Build the Docker image
make bootstrap

# 3. Start the server
make up

# 4. Run the full demo (attack simulation + metric export)
make demo
```
### Running Tests Locally

```bash
pip install -r requirements.txt
make test
```

Output includes per-file coverage summary. Fails if coverage drops below 70%.

### Viewing Logs

```bash
# Docker logs
make logs

# Request log CSV (after demo)
cat artifacts/release/logs.csv

# Alert log
cat artifacts/release/alerts.json   # created when server is running

# Live metrics
make metrics
```

### Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `LOG_SECRET` | `changeme-in-production` | HMAC key for tamper-evident logs |
| `LOG_DIR` | `.` | Directory where logs are written |
| `FLASK_ENV` | `production` | Set to `development` for debug mode |

Set `LOG_SECRET` via `.env` file or shell export before `make up`.

## Demo Video 

watch demo video here: https://youtu.be/yqHrpu_F5IU
