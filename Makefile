.PHONY: up down logs status check-backend

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
