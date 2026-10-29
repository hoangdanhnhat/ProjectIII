# DFIR/CA evidence collector - Docker lab helpers.
#
# Prerequisites: docker + compose v2, openssl. Full guide: deploy/docker/README.md
# Typical session (server + Windows agent topology):
#   make lab-init && make lab-up && make lab-job SCENARIO=netstat.v1
# Full lab with the monitored Linux web host (web profile):
#   make lab-up-web && make lab-traffic && make lab-job
#
# The lab runs plain HTTP (no certificates) for now; see compose.yaml for the
# note on HTTPS being a later phase.

SHELL := /bin/sh
ENV_FILE := .env
BASE := http://localhost:8080
SCENARIO ?= webshell.v1

.PHONY: help lab-init lab-up lab-up-web lab-down lab-logs lab-traffic lab-job lab-status lab-clean

help: ## show this help
	@grep -E '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "  %-12s %s\n", $$1, $$2}'

lab-init: ## create .env tokens when missing (idempotent, safe to re-run)
	./deploy/docker/gen-env.sh

lab-up: lab-init ## build and start the SERVER ONLY (Windows agent is the collector)
	docker compose up -d --build

lab-up-web: lab-init ## build and start server + monitored Linux web host (profile "web")
	docker compose --profile web up -d --build

lab-down: ## stop the lab (keeps data/ and .env)
	docker compose --profile web down

lab-logs: ## follow logs of the running containers
	docker compose --profile web logs -f

lab-traffic: ## 5 requests to the uploads fixture (requires 'make lab-up-web')
	@docker compose ps web 2>/dev/null | grep -q dfir-lab-web || { echo "web container is not running - use 'make lab-up-web' (note: it competes with a Windows agent for jobs)"; exit 1; }; \
	set -a; . ./$(ENV_FILE); set +a; \
	i=0; while [ $$i -lt 5 ]; do \
	  curl -fsS -o /dev/null "http://localhost:$${WEB_PORT:-8081}/uploads/fixture.php" || exit 1; \
	  i=$$((i+1)); \
	done; \
	echo "5 requests served by Apache - see the access.log snapshot in the next job"

lab-job: ## create a $(SCENARIO) job and wait for it (e.g. SCENARIO=netstat.v1; optional SINCE=RFC3339)
	@test -f $(ENV_FILE) || { echo "run 'make lab-init' first"; exit 1; }; \
	set -a; . ./$(ENV_FILE); set +a; \
	since='$(SINCE)'; \
	scenario='$(SCENARIO)'; \
	body=$$(printf '{"host_id":"lab-ubuntu","scenario":"%s"' "$$scenario"; \
	  [ -n "$$since" ] && printf ',"since":"%s"' "$$since"; \
	  printf '}'); \
	resp=$$(curl -sS -X POST $(BASE)/v1/jobs \
	  -H "Authorization: Bearer $${DFIR_OPERATOR_TOKEN}" \
	  -H 'Content-Type: application/json' -d "$$body"); \
	jobid=$$(printf '%s' "$$resp" | sed -n 's/^{"id":"\([0-9a-f]\{32\}\)".*/\1/p'); \
	if [ -z "$$jobid" ]; then echo "could not create job:"; printf '%s\n' "$$resp"; exit 1; fi; \
	echo "job $$jobid created ($$scenario), waiting for the agent..."; \
	out=''; status=''; \
	for i in $$(seq 1 30); do \
	  out=$$(curl -sS -H "Authorization: Bearer $${DFIR_OPERATOR_TOKEN}" $(BASE)/v1/jobs/$$jobid); \
	  status=$$(printf '%s' "$$out" | sed -n 's/.*"status":"\([a-z_]*\)".*/\1/p'); \
	  case $$status in queued|running) sleep 2;; *) break;; esac; \
	done; \
	n=$$(printf '%s' "$$out" | grep -o '"kind"' | wc -l); \
	echo "status: $$status, artifacts: $$n"; \
	printf '%s\n' "$$out" | (python3 -m json.tool 2>/dev/null || cat)

lab-status: ## list jobs (newest first)
	@test -f $(ENV_FILE) || { echo "run 'make lab-init' first"; exit 1; }; \
	set -a; . ./$(ENV_FILE); set +a; \
	curl -sS -H "Authorization: Bearer $${DFIR_OPERATOR_TOKEN}" $(BASE)/v1/jobs \
	  | (python3 -m json.tool 2>/dev/null || cat)

lab-clean: ## stop the lab and delete data/, .env and leftover certs (full reset)
	docker compose --profile web down --remove-orphans
	-docker compose run --rm --no-deps --entrypoint /bin/sh dfir-server \
	  -c 'rm -rf /data/artifacts /data/jobs /data/audit.jsonl'
	rm -rf data .env deploy/docker/certs
	echo "lab reset. start over with: make lab-up"
