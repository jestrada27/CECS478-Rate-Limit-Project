.PHONY: bootstrap up down demo clean test logs export ci-check

# ── Setup ─────────────────────────────────────────────────────────────────────

bootstrap:
	docker compose build

# ── Runtime ───────────────────────────────────────────────────────────────────

up:
	docker compose up -d
	@echo "Waiting for server to start..."
	@sleep 2
	@curl -sf http://localhost:5000/health > /dev/null && echo "Server is up!" || echo "Server may still be starting"

down:
	docker compose down

# ── Demo vertical slice ───────────────────────────────────────────────────────
# Runs attack simulation + exports metrics artifacts
# Usage: make up && make demo

demo:
	@mkdir -p artifacts/release
	python3 scripts/attack_sim.py
	python3 scripts/export_metrics.py

# ── Testing ───────────────────────────────────────────────────────────────────

test:
	pytest tests/ -v --cov=app --cov-report=term-missing --cov-report=json:artifacts/release/coverage.json

test-ci:
	pytest tests/ --cov=app --cov-report=term-missing --cov-fail-under=70

# ── Observability ─────────────────────────────────────────────────────────────

export:
	@mkdir -p artifacts/release
	python3 scripts/export_metrics.py

logs:
	docker compose logs -f web

metrics:
	@curl -s http://localhost:5000/metrics | python3 -m json.tool

# ── Cleanup ───────────────────────────────────────────────────────────────────

clean:
	docker compose down -v
	rm -f logs.csv logs.json alerts.json
	rm -f artifacts/release/logs.csv artifacts/release/alerts.json
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete

# ── CI local check ────────────────────────────────────────────────────────────

ci-check:
	@echo "Running full CI check locally..."
	pip install -r requirements.txt -q
	$(MAKE) test-ci
	@echo "CI check passed."
