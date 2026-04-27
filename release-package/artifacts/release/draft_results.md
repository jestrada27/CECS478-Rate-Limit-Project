# Draft Results — Evaluation in Progress

**Status:** Initial data collected. Final analysis due Week 16.

---

## What We're Observing

### Traffic Simulation Setup

Two traffic profiles were simulated inside the Docker environment:

| Profile | Client IP | Requests | Delay |
|---|---|---|---|
| Normal user | `127.0.0.1` | 10 | 300ms between |
| Attack bot | `10.0.0.2` | 30 | ~0ms (burst) |

---

### Rate Limiting Effectiveness

From `per_ip_stats.csv`:

| Client | Allowed | Suspicious | Blocked | Total |
|---|---|---|---|---|
| 127.0.0.1 (normal) | 10 | 0 | 0 | 10 |
| 10.0.0.2 (attacker) | 15 | 5 | 10 | 30 |

**Key observation:** The normal user was never blocked or flagged. The attacker was allowed through the first 15 requests (below threshold), flagged as suspicious for requests 16–20, then blocked for all requests 21–30.

**Block rate against attacker:** 10/30 = **33%** of total attacker requests blocked, 100% of requests past the limit.

---

### Suspicious Activity Detection

The `ALERT_THRESHOLD` (default 15) successfully caught escalating behavior before hard blocking. This two-tier approach (suspicious → blocked) provides early warning without immediately cutting off marginal cases.

---

### False Positive Rate

In initial tests: **0 false positives** under normal traffic. The 300ms-spaced normal client never crossed the alert threshold within the 60-second sliding window.

Planned: Run a synthetic "bursty but legitimate" traffic test (e.g., 18 requests in 60s) to characterize the gray zone near the threshold.

---

### Response Time (preliminary)

| Condition | Avg Response |
|---|---|
| Below limit | ~2ms |
| At threshold | ~2ms |
| Blocked (429) | ~1ms (early return) |

Rate limiting does not degrade response time for legitimate users. Blocked responses are marginally faster (early return before route handler).

---

## What's Next for Week 16

- [ ] Increase traffic volume (1000+ requests) to stress-test throughput
- [ ] Generate PCAP files with `tcpdump` capturing the attack simulation
- [ ] Measure response time under concurrent attacker + normal user load
- [ ] Tune `WINDOW_SECONDS` and `REQUEST_LIMIT` and document impact on false positive rate
- [ ] Produce response-time comparison chart (before/after rate limiting active)
- [ ] Calculate precision/recall of the suspicious-flag classifier
