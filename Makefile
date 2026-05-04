.PHONY: bootstrap up down demo clean test logs

bootstrap:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

demo:
	python3 scripts/attack_sim.py

clean:
	docker compose down -v
	rm -f logs.csv logs.json alerts.json
	rm -f artifacts/release/logs.csv artifacts/release/alerts.json
	rm -f artifacts/release/metrics_summary.json artifacts/release/per_ip_stats.csv
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -delete

test:
	@echo "Test target stub - add unit and integration tests here"

logs:
	docker compose logs -f web
