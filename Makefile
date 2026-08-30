.DEFAULT_GOAL := help
SHELL := /bin/sh

# Targets are added by the commit that introduces the thing they operate on, so this file
# never advertises a command that cannot work yet. Migration, seed and demo targets arrive
# with the chunks that introduce them.

COMPOSE ?= docker compose
UV ?= uv
BACKEND := backend

.PHONY: help bootstrap bootstrap-force verify-ignore require-env compose-config \
        build up down compose-ps compose-logs compose-down compose-test pin-digests clean \
        backend-install lint format format-check typecheck test test-cov check

help: ## Show available targets
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

## ---------------------------------------------------------------- environment

bootstrap: ## Create .env with random development-only secrets (idempotent, never overwrites)
	python3 infra/scripts/bootstrap_env.py

bootstrap-force: ## Regenerate .env, overwriting the existing file
	python3 infra/scripts/bootstrap_env.py --force

## ---------------------------------------------------------------- backend quality

# These run natively via uv and need no containers, so they work before the stack builds.

backend-install: ## Install the backend's locked dependency set
	cd $(BACKEND) && $(UV) sync --frozen

lint: ## Lint the backend sources and tests
	cd $(BACKEND) && $(UV) run ruff check src tests

format: ## Reformat the backend in place
	cd $(BACKEND) && $(UV) run ruff format src tests

format-check: ## Fail if the backend is not formatted
	cd $(BACKEND) && $(UV) run ruff format --check src tests

typecheck: ## Typecheck the backend
	cd $(BACKEND) && $(UV) run mypy

# The suite is hermetic: it fakes the PostgreSQL and Redis probes and reads the committed
# manifests as data, so it needs no container. ENV=test is what lets the settings object
# accept the placeholder secrets from .env.example.
test: ## Run the backend test suite (unit, integration, security)
	cd $(BACKEND) && ENV=test $(UV) run pytest

test-cov: ## Run the suite with a coverage report
	cd $(BACKEND) && ENV=test $(UV) run pytest --cov=aegisnet --cov-report=term-missing

check: verify-ignore lint format-check typecheck test ## Run every check that works today

## ---------------------------------------------------------------- safety checks

verify-ignore: ## Prove that secrets, captures, and local artefacts cannot be committed
	@fail=0; \
	for path in .env .env.local secret.pem capture.pcap capture.pcapng eve.json \
	            app.log logs/suricata.log pgdata/base coverage.xml .coverage \
	            node_modules/x .next/build backend/.pytest_cache/x samples/external/set.zip \
	            docker-compose.override.yml; do \
		if git check-ignore -q "$$path"; then \
			printf '  ignored      %s\n' "$$path"; \
		else \
			printf '  NOT IGNORED  %s\n' "$$path"; fail=1; \
		fi; \
	done; \
	for path in .env.example README.md Makefile docker-compose.yml \
	            docker-compose.override.yml.example; do \
		if git check-ignore -q "$$path"; then \
			printf '  WRONGLY IGNORED  %s\n' "$$path"; fail=1; \
		else \
			printf '  tracked      %s\n' "$$path"; \
		fi; \
	done; \
	if [ "$$fail" -ne 0 ]; then echo "verify-ignore FAILED"; exit 1; fi; \
	echo "verify-ignore OK"

## ---------------------------------------------------------------- compose

require-env: ## Fail unless .env exists (Compose interpolation needs it)
	@test -f .env || { \
		echo "error: .env is missing. Run 'make bootstrap' first." >&2; exit 1; }

compose-config: require-env ## Validate and render the Compose manifests without starting anything
	$(COMPOSE) config --quiet
	$(COMPOSE) -f docker-compose.test.yml config --quiet
	@echo "compose-config OK"

build: require-env ## Build the api, worker and web images
	$(COMPOSE) build

# The Milestone 1 gate from ADR-011: `make bootstrap && make up`. Every service has a
# healthcheck, so --wait returns only once all five report healthy (or fails after the
# timeout, printing which dependency did not come up).
up: require-env ## Build if needed, start the stack and wait until every service is healthy
	$(COMPOSE) up --build --detach --wait --wait-timeout 240
	@echo "api:  http://127.0.0.1:8000/healthz  /readyz  /docs"
	@echo "web:  http://127.0.0.1:3000/"

down: ## Stop the stack and remove the database volume
	$(COMPOSE) down --volumes --remove-orphans

compose-ps: ## Show stack status
	$(COMPOSE) ps

compose-logs: ## Tail stack logs
	$(COMPOSE) logs --tail=200 -f

compose-down: ## Stop the stack, keeping the database volume
	$(COMPOSE) down --remove-orphans

compose-test: ## Run the backend suite inside the hermetic test-runner container
	$(COMPOSE) -f docker-compose.test.yml run --rm --build tests

# Decision F-5: images are pinned by minor tag, not digest. This prints the digests to paste
# into docker-compose.yml when F-5 is applied; it does not edit any file.
pin-digests: ## Print manifest-list digests for the pinned base images
	@for image in postgres:16-alpine redis:7-alpine python:3.12-slim-bookworm node:20-alpine \
	              ghcr.io/astral-sh/uv:python3.12-bookworm-slim; do \
		printf '%-52s ' "$$image"; \
		docker buildx imagetools inspect "$$image" --format '{{.Manifest.Digest}}' 2>/dev/null \
			|| echo "(unavailable)"; \
	done

clean: ## Remove local caches and build artefacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
