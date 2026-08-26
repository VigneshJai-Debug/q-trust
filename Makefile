# Q-Trust — delegating facade (polyglot monorepo table of contents)
# Usage: make <target>  — delegates to the owning subsystem.
.PHONY: help test scan up down verify docs
help:
	@echo "Targets: test | scan | up | down | verify | docs"
	@echo "  test   — all tests (forge + pytest + vitest)"
	@echo "  scan   — crypto-inspector scan ./src"
	@echo "  up     — docker compose up --build"
	@echo "  down   — docker compose down"
	@echo "  verify — ./scripts/verify_all.sh"
	@echo "  docs   — mkdocs build --strict"
test:
	cd contracts && forge test
	cd inspector && pytest -q
	cd sdk && pytest -q
	cd backend && npm test
	cd frontend && npm test
scan:
	crypto-inspector scan ./src --cyclonedx cbom.json --risk
up:
	docker compose up -d --build
down:
	docker compose down
verify:
	./scripts/verify_all.sh
docs:
	mkdocs build --strict
