.PHONY: up down logs demo check

up:
	docker compose up --build --detach

down:
	docker compose down

logs:
	docker compose logs --follow

demo:
	./scripts/demo-check.sh

check:
	cd backend && go vet ./... && go test ./...
	cd backend/ml-service && python3 -m pytest
	cd frontend && npm run lint && npm run build
