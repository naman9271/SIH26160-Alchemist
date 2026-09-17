.PHONY: up down logs status check-backend

PROFILE ?= tunnel-v4-cbc128-pfs
TRAFFIC ?= web
SECONDS ?= 10
SEED ?= 42
.PHONY: lab-up lab-run lab-verify lab-down lab-list lab-test
lab-up:
	python3 lab/labctl.py up --profile $(PROFILE)
lab-run:
	python3 lab/labctl.py run --profile $(PROFILE) --traffic $(TRAFFIC) --seconds $(SECONDS) --seed $(SEED)
lab-verify:
	python3 lab/labctl.py verify --profile $(PROFILE)
lab-down:
	python3 lab/labctl.py down
lab-list:
	python3 lab/labctl.py list
lab-test:
	python3 -m unittest discover -s lab/tests -v

up:
	docker compose up --build --detach

down:
	docker compose down

logs:
	docker compose logs --follow

status:
	docker compose ps

check-backend:
	cd backend && go vet ./... && go test ./...
	cd backend/ml-service && python3 -m pytest
