import pytest
import time
import os
import csv
import sys

os.environ["LOG_DIR"] = "/tmp"

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.main import app, request_windows, stats, REQUEST_LIMIT, ALERT_THRESHOLD, LOG_DIR, CSV_LOG


@pytest.fixture
def client():
    app.config["TESTING"] = True
    request_windows.clear()
    stats["total_allowed"] = 0
    stats["total_blocked"] = 0
    stats["total_suspicious"] = 0
    if os.path.exists(CSV_LOG):
        os.remove(CSV_LOG)
    with app.test_client() as c:
        yield c


# Alpha: Minimal tests 

class TestAlpha:
    def test_home_returns_200(self, client):
        """Happy path: home endpoint responds successfully."""
        resp = client.get("/")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"

    def test_blocked_after_limit(self, client):
        """Negative: requests exceeding the limit are rejected with 429."""
        for _ in range(REQUEST_LIMIT):
            resp = client.get("/")
            assert resp.status_code == 200

        resp = client.get("/")
        assert resp.status_code == 429
        data = resp.get_json()
        assert data["status"] == "blocked"


# Beta: Robust tests 

class TestBeta:
    def test_health_endpoint(self, client):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["status"] == "ok"
        assert "uptime_start" in data

    def test_metrics_endpoint(self, client):
        resp = client.get("/metrics")
        assert resp.status_code == 200
        data = resp.get_json()
        for field in ("total_allowed", "total_blocked", "total_suspicious", "active_clients"):
            assert field in data

    def test_metrics_csv_endpoint(self, client):
        resp = client.get("/metrics/csv")
        assert resp.status_code == 200
        assert "text/csv" in resp.content_type
        lines = resp.data.decode().strip().splitlines()
        assert lines[0] == "metric,value"
        assert len(lines) > 1

    def test_data_endpoint(self, client):
        resp = client.get("/data")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "payload" in data

    def test_unknown_route_returns_404_not_blocked(self, client):
        """Edge case: unknown routes return 404, not a rate-limit error."""
        resp = client.get("/this-does-not-exist")
        assert resp.status_code == 404

    def test_exactly_at_limit_is_allowed(self, client):
        """Edge case: the REQUEST_LIMIT-th request itself is still allowed."""
        for i in range(REQUEST_LIMIT):
            resp = client.get("/")
            assert resp.status_code == 200

        resp = client.get("/")
        assert resp.status_code == 429

    def test_x_forwarded_for_ip_respected(self, client):
        """Edge case: X-Forwarded-For header is used as the client IP."""
        for _ in range(REQUEST_LIMIT):
            client.get("/", headers={"X-Forwarded-For": "9.9.9.9"})

        resp = client.get("/", headers={"X-Forwarded-For": "9.9.9.9"})
        assert resp.status_code == 429

        resp = client.get("/", headers={"X-Forwarded-For": "8.8.8.8"})
        assert resp.status_code == 200

    def test_suspicious_threshold_tracked(self, client):
        """Edge case: requests between ALERT_THRESHOLD and REQUEST_LIMIT are tracked as suspicious."""
        for _ in range(ALERT_THRESHOLD - 1):
            client.get("/")

        before = stats["total_suspicious"]
        client.get("/")
        after = stats["total_suspicious"]
        assert after > before

    def test_blocked_requests_increments_counter(self, client):
        """Negative: blocked counter increments when rate limit fires."""
        for _ in range(REQUEST_LIMIT + 1):
            client.get("/")
        assert stats["total_blocked"] >= 1

    def test_csv_log_created_with_headers(self, client):
        """Integration: CSV log file is created with correct headers on first request."""
        client.get("/")

        assert os.path.exists(CSV_LOG), f"Expected log at {CSV_LOG}"
        with open(CSV_LOG, newline="") as fh:
            reader = csv.reader(fh)
            headers = next(reader)
        assert "timestamp" in headers
        assert "client_ip" in headers
        assert "status" in headers
        assert "hmac" in headers
