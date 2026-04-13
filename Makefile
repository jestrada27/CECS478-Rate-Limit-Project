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
	rm -f logs.json logs.csv

test:
	@echo "Test target stub - add unit and integration tests here"

logs:
	docker compose logs -f web
