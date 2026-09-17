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
	./lab/scripts/up.sh

lab-down:
	docker compose -f lab/compose.yaml down --remove-orphans

lab-run:
	@test -n "$(PROFILE)" || (echo "Use PROFILE=lab/profiles/<profile>.yaml" >&2; exit 2)
	./lab/scripts/run.sh "$(PROFILE)"

lab-verify:
	@test -n "$(PROFILE)" || (echo "Use PROFILE=lab/profiles/<profile>.yaml" >&2; exit 2)
	./lab/scripts/verify.sh "$(PROFILE)"

lab-profile-check:
	@for profile in lab/profiles/*.yaml; do python3 lab/scripts/profile.py "$$profile" >/dev/null; done

lab-test: lab-profile-check
	python3 -m unittest lab/tests/test_profiles.py
