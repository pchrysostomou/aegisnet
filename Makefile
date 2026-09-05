.DEFAULT_GOAL := help
SHELL := /bin/sh

# Targets are added by the commit that introduces the thing they operate on, so this file
# never advertises a command that cannot work yet. Seed and demo targets arrive with the
# chunks that introduce them.

COMPOSE ?= docker compose
UV ?= uv
BACKEND := backend

.PHONY: lab-preflight lab-up lab-traffic lab-capture lab-export lab-sanitize lab-down lab-clean eval-lab test-security \
        test-detectors gen-fixtures eval run-detectors alerts recompute-baselines baselines create-user users create-service-token revoke-service-token service-tokens \
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
	cd $(BACKEND) && $(UV) run ruff check --config pyproject.toml src tests ../tools ../infra/lab
	cd $(BACKEND) && $(UV) run lint-imports

format: ## Reformat the backend and tools/ in place
	cd $(BACKEND) && $(UV) run ruff format --config pyproject.toml src tests ../tools ../infra/lab

format-check: ## Fail if the backend or tools/ is not formatted
	cd $(BACKEND) && $(UV) run ruff format --check --config pyproject.toml src tests ../tools ../infra/lab

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
	            infra/lab/out/eve.json infra/lab/out/suricata.log infra/lab/out/stats.log \
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

compose-config: require-env ## Validate and render every Compose manifest without starting anything
	$(COMPOSE) config --quiet
	$(COMPOSE) -f docker-compose.test.yml config --quiet
	$(COMPOSE) -f $(LAB_COMPOSE) --profile lab config --quiet
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

## ---------------------------------------------------------------- the isolated lab (ADR-021)

# Opt-in and separate from the application stack. Nothing here runs unless a target below
# is invoked, and every service carries the `lab` profile so even `docker compose -f
# infra/lab/docker-compose.lab.yml up` starts nothing without it. The pre-flight checklist
# these targets automate is docs/evaluation.md §7 (L-0 .. L-5).
LAB_COMPOSE := infra/lab/docker-compose.lab.yml
LAB := $(COMPOSE) -f $(LAB_COMPOSE) --profile lab
LAB_CAPTURE := infra/lab/out/eve.json
LAB_EXCERPT := samples/lab/lab-capture-01.ndjson
LAB_LIMIT ?= 500
SCENARIOS ?= benign,auth,sweep,beacon,bulk,dns

lab-preflight: ## L-0/L-1: prove the lab network is internal, has no default route, and holds only lab containers
	@$(LAB) up -d --build target >/dev/null
	@echo "L-0 network:"
	@docker network inspect aegisnet_lab --format '  Internal={{.Internal}} Subnet={{range .IPAM.Config}}{{.Subnet}}{{end}}'
	@echo "L-0 default route inside the lab (expect none):"
	@$(LAB) exec -T target python -c "import sys; rows=[l.split() for l in open('/proc/net/route').read().splitlines()[1:]]; d=[r for r in rows if r[1]=='00000000']; print('  default routes:', d or 'none'); sys.exit(1 if d else 0)"
	@echo "L-1 containers attached to aegisnet_lab:"
	@docker network inspect aegisnet_lab --format '{{range .Containers}}  {{.Name}} {{.IPv4Address}}{{"\n"}}{{end}}'

lab-up: ## Start the lab target and the Suricata sensor (no traffic yet)
	$(LAB) up -d --build --force-recreate target suricata

lab-traffic: ## Generate the shaped lab traffic (SCENARIOS=benign,auth,sweep,beacon,bulk,dns)
	$(LAB) run --rm generator python /lab/generate.py \
	  --wait-for /capture/suricata.log --scenarios $(SCENARIOS)

lab-capture: ## One full run: clean, pre-flight, sensor up, traffic, flush, export — writes infra/lab/out/eve.json
	$(MAKE) lab-clean
	$(MAKE) lab-preflight
	$(MAKE) lab-up
	$(MAKE) lab-traffic
	@sleep 3
	$(LAB) stop suricata
	$(MAKE) lab-export

lab-export: ## Copy this run's EVE output out of the sensor's volume onto the operator's disk
	@mkdir -p infra/lab/out
	$(LAB) cp suricata:/capture/eve.json $(LAB_CAPTURE)
	@$(LAB) cp suricata:/capture/suricata.log infra/lab/out/suricata.log 2>/dev/null || true
	@wc -l < $(LAB_CAPTURE) | xargs -I{} echo "captured {} EVE records in $(LAB_CAPTURE)"

lab-sanitize: ## L-5: sanitise the capture into samples/lab/ (LAB_LIMIT=500, enough for one default run)
	python3 tools/sanitize_eve.py --in $(LAB_CAPTURE) --out $(LAB_EXCERPT) --limit $(LAB_LIMIT)
	python3 tools/sanitize_eve.py --check $(LAB_EXCERPT)

lab-down: ## Stop the lab and remove its network (the capture volume survives)
	$(LAB) down --remove-orphans

lab-clean: ## Remove the lab, its capture volume and any exported capture; samples/lab/ is kept
	$(LAB) down --volumes --remove-orphans
	rm -f infra/lab/out/eve.json infra/lab/out/suricata.log infra/lab/out/stats.log

eval-lab: require-env ## T3 qualitative run: ingest the sanitised lab capture and sweep it (needs `make up`)
	$(COMPOSE) run --rm api python -m aegisnet.cli seed-assets lab-capture
	$(COMPOSE) run --rm api python -m aegisnet.cli import-dataset lab-capture-01 --source-label lab-suricata
	@# The window comes from the capture's own manifest, so the sweep covers exactly the
	@# hour the lab ran. Kept in a shell variable rather than a file: nothing here needs to
	@# write to a fixed path outside the repository.
	@window=$$(python3 -c "import json; w=json.load(open('samples/lab/lab-capture-01.manifest.json'))['sweep_window']; print(w['from'], w['to'])"); \
	  set -- $$window; \
	  echo "sweeping $$1 .. $$2"; \
	  $(COMPOSE) run --rm api python -m aegisnet.cli run-detectors --from $$1 --to $$2
	$(COMPOSE) run --rm api python -m aegisnet.cli alerts --limit 20

test-security: ## Run the security-marked tests (compose policy, payload limits, RBAC, the lab)
	cd $(BACKEND) && ENV=test $(UV) run pytest -m security

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

## ---------------------------------------------------------------- detection

# The detector suite alone: bounds, severity, every rule and every labelled fixture
# (docs/detection-rules.md, ADR-017). Part of the hermetic suite too.
test-detectors: ## Run the detector suite (rules, severity, labelled fixtures)
	cd $(BACKEND) && ENV=test $(UV) run pytest tests/detectors

# A detection sweep over an interval of at most 24 hours (ADR-018). MODE=async hands it
# to the worker and prints the message id; sync runs it in the api image and prints one
# run per rule, exiting 1 if any rule raised.
FROM ?= 2026-09-01T00:00:00Z
TO ?= 2026-09-01T02:00:00Z
run-detectors: require-env ## Run every detection rule over [FROM, TO) (MODE=sync|async)
	$(COMPOSE) run --rm api python -m aegisnet.cli run-detectors --from $(FROM) --to $(TO) --mode $(MODE)

# The baseline job behind D-005 (ADR-019): one asset_baselines row per asset with outbound
# history in the last WINDOW_DAYS. Chunk 12 schedules it; until then run it by hand.
WINDOW_DAYS ?= 7
recompute-baselines: require-env ## Summarise each asset's outbound history into asset_baselines (WINDOW_DAYS=7, MODE=sync|async)
	$(COMPOSE) run --rm api python -m aegisnet.cli recompute-baselines --window-days $(WINDOW_DAYS) --mode $(MODE)

baselines: require-env ## List the stored baselines
	$(COMPOSE) run --rm api python -m aegisnet.cli baselines

LIMIT ?= 20
alerts: require-env ## List alerts, newest first (LIMIT=20)
	$(COMPOSE) run --rm api python -m aegisnet.cli alerts --limit $(LIMIT)

# Regenerates the labelled T1 fixtures from tools/gen_labelled_fixtures.py. A test fails
# until the regenerated files are committed, so a case change is always reviewable.
gen-fixtures: ## Regenerate backend/tests/fixtures/labelled from the case definitions
	python3 tools/gen_labelled_fixtures.py --out backend/tests/fixtures/labelled

# T1 = the labelled cases, T2 = the benign synthetic corpus; rewrites the marked block in
# docs/evaluation.md §8. A test pins that block, so run this after touching a rule. The
# command takes no paths: it finds the checkout above its working directory.
eval: ## Score the rules on the labelled cases and the benign corpus; refresh docs/evaluation.md §8
	cd $(BACKEND) && uv run python -m aegisnet.cli eval-detectors

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
