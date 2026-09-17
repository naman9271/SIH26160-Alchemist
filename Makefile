.PHONY: up down logs status check-backend lab-up lab-down lab-run lab-verify lab-profile-check lab-test

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

lab-up:
	cd backend && bash ./lab/scripts/managed.sh activate

lab-down:
	docker compose -f backend/lab/compose.yaml down --remove-orphans

lab-run:
	cd backend && bash ./lab/scripts/managed.sh generate "lab/output/$$(date -u +%Y%m%dT%H%M%SZ)" "$(or $(PROFILES),1)" "$(or $(LABELS),icmp)" "$(or $(REPETITIONS),1)"

lab-verify:
	docker compose -f backend/lab/compose.yaml ps
	docker exec managed-ipsec-left ipsec statusall

lab-profile-check:
	python3 -m unittest discover -s backend/lab/tests -p 'test_*.py'

lab-test: lab-profile-check
	@for script in backend/lab/scripts/*.sh backend/lab/docker/*.sh; do bash -n "$$script"; done
