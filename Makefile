.PHONY: up down build logs seed import detect test-backend test-frontend

up:
	docker compose up --build

down:
	docker compose down

build:
	docker compose build

logs:
	docker compose logs -f backend worker frontend

seed:
	docker compose run --rm backend python ../scripts/seed_demo_data.py

import:
	docker compose run --rm backend python ../scripts/import_demo_logs.py

detect:
	docker compose run --rm backend python ../scripts/run_detection_once.py

test-backend:
	cd backend && python -m pytest tests -q

test-frontend:
	cd frontend && npm test
