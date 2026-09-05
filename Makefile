.DEFAULT_GOAL := help
SHELL := /bin/sh

# Targets are added by the commit that introduces the thing they operate on, so this file
# never advertises a command that cannot work yet. Seed and demo targets arrive with the
# chunks that introduce them.

COMPOSE ?= docker compose
UV ?= uv
BACKEND := backend

.PHONY: create-user users create-service-token revoke-service-token service-tokens \
        help bootstrap bootstrap-force verify-ignore require-env compose-config \
        build up down compose-ps compose-logs compose-down compose-test pin-digests clean \
        backend-install lint format format-check typecheck test test-cov check \
        migrate migrate-status test-db gen-synthetic demo-ingest batch seed

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

# ruff covers the backend, the generator in tools/ and the bootstrap script; lint-imports
# enforces the layering contracts in pyproject.toml (ARCHITECTURE §1: domain/ is pure).
lint: ## Lint the backend, tools/ and infra/scripts, and check the import contracts
	cd $(BACKEND) && $(UV) run ruff check --config pyproject.toml src tests ../tools
	cd $(BACKEND) && $(UV) run lint-imports

format: ## Reformat the backend and tools/ in place
	cd $(BACKEND) && $(UV) run ruff format --config pyproject.toml src tests ../tools

format-check: ## Fail if the backend or tools/ is not formatted
	cd $(BACKEND) && $(UV) run ruff format --check --config pyproject.toml src tests ../tools

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

## ---------------------------------------------------------------- database

# Migrations run inside the api image as the migrator role (env.py reads the migrator
# credentials from .env); the runtime role never holds DDL rights (THREAT_MODEL T-5.3).
migrate: require-env ## Apply every pending migration (alembic upgrade head)
	$(COMPOSE) run --rm api alembic upgrade head

migrate-status: require-env ## Show the revision the database holds and the head this build expects
	$(COMPOSE) run --rm api alembic current
	$(COMPOSE) run --rm api alembic heads

# The database suite: migrations, grants and schema/ORM agreement against an ephemeral
# PostgreSQL 16 (docker-compose.test.yml, profile db). Tears down the database and its
# anonymous volume whether the suite passes or fails, and preserves the exit status.
test-db: require-env ## Run the database suite against an ephemeral PostgreSQL 16
	$(COMPOSE) -f docker-compose.test.yml --profile db run --rm --build tests-db; \
	status=$$?; \
	$(COMPOSE) -f docker-compose.test.yml --profile db down --volumes --remove-orphans; \
	exit $$status

## ---------------------------------------------------------------- datasets

# The Milestone 1 demo path (ADR-014): import the registered synthetic corpus through the
# api image. Runs synchronously and prints the finished batch; a second run stores zero
# new events and reports every line as a duplicate. MODE=async enqueues it for the worker
# instead and prints the batch id to poll with `make batch ID=<uuid>`.
DATASET ?= synthetic-benign-baseline-01
LABEL ?= demo-run
MODE ?= sync
demo-ingest: require-env ## Ingest the registered synthetic corpus (DATASET=, LABEL=, MODE=sync|async)
	$(COMPOSE) run --rm api python -m aegisnet.cli import-dataset $(DATASET) \
		--source-label $(LABEL) --mode $(MODE)

batch: require-env ## Show an ingest batch by id (ID=<uuid>)
	$(COMPOSE) run --rm api python -m aegisnet.cli batch $(ID)

# Upserts the lab inventory by hostname from samples/assets/$(SEED).yml (Chunk 5, ADR-015).
SEED ?= lab-assets
seed: require-env ## Seed the asset inventory (SEED=lab-assets)
	$(COMPOSE) run --rm api python -m aegisnet.cli seed-assets $(SEED)

## ---------------------------------------------------------------- users and tokens

# Users and ingest service tokens are created through the api image (Chunk 6, ADR-016).
# The password never appears in argv: it is prompted without echo on a terminal, or read
# from a pipe (`printf '%s\n' "$$PW" | make create-user EMAIL=... ROLE=admin`). A service
# token is printed exactly once and stored only as a sha256 hash.
ROLE ?= analyst
TTL_DAYS ?= 90
create-user: require-env ## Create a user (EMAIL=, ROLE=admin|analyst|viewer); password from stdin
	@test -n "$(EMAIL)" || { echo "EMAIL=<address> is required"; exit 2; }
	@if [ -t 0 ]; then \
	    printf 'Password for $(EMAIL) (not echoed): '; stty -echo; read -r pw; stty echo; printf '\n'; \
	    printf '%s\n' "$$pw"; \
	else cat; fi | $(COMPOSE) run --rm -T api python -m aegisnet.cli create-user $(EMAIL) \
	    --role $(ROLE) --password-stdin

users: require-env ## List users (never hashes)
	$(COMPOSE) run --rm -T api python -m aegisnet.cli users

create-service-token: require-env ## Mint an ingest service token (NAME=, TTL_DAYS=90); printed once
	@test -n "$(NAME)" || { echo "NAME=<label> is required"; exit 2; }
	$(COMPOSE) run --rm -T api python -m aegisnet.cli create-service-token $(NAME) --ttl-days $(TTL_DAYS)

revoke-service-token: require-env ## Revoke a service token (ID=<uuid>)
	$(COMPOSE) run --rm -T api python -m aegisnet.cli revoke-service-token $(ID)

service-tokens: require-env ## List service tokens (never hashes)
	$(COMPOSE) run --rm -T api python -m aegisnet.cli service-tokens

# Regenerates the committed synthetic corpus byte-for-byte (seeded). After changing the
# generator, run this, then update sha256 in samples/registry.yml; the integration suite
# fails until the checksum matches.
gen-synthetic: ## Regenerate samples/synthetic/benign-baseline-01 from its fixed seed
	python3 tools/gen_synthetic_eve.py --seed 20260905 --events 2000 \
		--out samples/synthetic/benign-baseline-01.ndjson

# Decision F-5: images are pinned by minor tag, not digest. This prints the digests to paste
# into docker-compose.yml when F-5 is applied; it does not edit any file.
pin-digests: ## Print manifest-list digests for the pinned base images
	@for image in postgres:16-alpine redis:7-alpine python:3.12-slim-bookworm node:22-alpine \
	              ghcr.io/astral-sh/uv:python3.12-bookworm-slim; do \
		printf '%-52s ' "$$image"; \
		docker buildx imagetools inspect "$$image" --format '{{.Manifest.Digest}}' 2>/dev/null \
			|| echo "(unavailable)"; \
	done

clean: ## Remove local caches and build artefacts
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -name __pycache__ -type d -prune -exec rm -rf {} +
