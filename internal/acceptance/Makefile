# E2E Acceptance Testing Makefile

.PHONY: help deps up down wait seed cleanup-users test test-mode-headed test-mode-debug test-suite-authn test-suite-authz test-suite-headers test-headed test-debug test-authn test-authz test-headers test-go logs status report artifacts clean

COMPOSE_PROJECT ?= acceptance
COMPOSE_FILE ?= docker-compose.yml
BROWSER_DIR ?= browser
ARTIFACTS_DIR ?= artifacts

# === Suite selection ===
# Usage: make test SUITE=mcp | make up SUITE=mcp | make down SUITE=mcp
# Default: base (no overlay files)
SUITE ?= base

# Build compose command from SUITE
COMPOSE_FILES := -f $(COMPOSE_FILE)
ifeq ($(SUITE),mcp)
  COMPOSE_FILES += -f docker-compose.mcp.yml
endif
ifeq ($(SUITE),all)
  COMPOSE_FILES += -f docker-compose.mcp.yml
endif

COMPOSE := docker compose $(COMPOSE_FILES) -p $(COMPOSE_PROJECT)

# Map SUITE to npm script
ifeq ($(SUITE),base)
  NPM_TEST_SCRIPT := test
else ifeq ($(SUITE),mcp)
  NPM_TEST_SCRIPT := test:mcp
else ifeq ($(SUITE),all)
  NPM_TEST_SCRIPT := test:all
else
  NPM_TEST_SCRIPT := test:$(SUITE)
endif

ifndef RUN_ID
  RUN_ID := $(shell date +%s)
endif
export RUN_ID
export COMPOSE_PROJECT_NAME := $(COMPOSE_PROJECT)

help:
	@echo "Acceptance test targets:"
	@echo "  make deps         - Install npm deps and Playwright browser"
	@echo "  make up           - Start the test stack"
	@echo "  make seed         - Seed Keycloak users"
	@echo "  make test         - Run Playwright tests (headless)"
	@echo "  make down         - Stop the stack"
	@echo "  make logs         - Tail container logs"
	@echo "  make status       - Show container and health status"
	@echo "  make report       - Show Playwright report"
	@echo "  make artifacts    - Collect artifacts"
	@echo "  make clean        - Stop stack and remove artifacts"
	@echo ""
	@echo "Suite selection (SUITE=base|mcp|all):"
	@echo "  make test              - Run base tests (59 tests)"
	@echo "  make test SUITE=mcp    - Run MCP tests (18 tests)"
	@echo "  make test SUITE=all    - Run all tests (77 tests)"
	@echo "  make up SUITE=mcp      - Start stack with MCP infrastructure"
	@echo "  make down SUITE=mcp    - Stop MCP stack"
	@echo ""
	@echo "Other modes:"
	@echo "  make test-mode-headed  - Run tests with a visible browser"
	@echo "  make test-mode-debug   - Run tests in debug mode"
	@echo "  make test-suite-authn  - Run authn tests"
	@echo "  make test-suite-authz  - Run authz tests"
	@echo "  make test-suite-headers - Run headers tests"
	@echo ""
	@echo "Environment: RUN_ID (default: timestamp), SUITE (default: base)"

# Dependencies
deps:
	cd $(BROWSER_DIR) && npm ci
	cd $(BROWSER_DIR) && npx playwright install chromium

# Start the test stack
up:
	$(COMPOSE) up -d --build

# Stop the test stack
down:
	$(COMPOSE) down -v

# Wait for stack readiness
wait:
	./scripts/wait-for-ready.sh

# Seed Keycloak with test users (runs inside Docker network for Keycloak 26 compatibility)
seed: wait
	docker run --rm --network acceptance_acceptance \
		-v $(CURDIR)/scripts:/scripts:ro \
		-v $(CURDIR)/fixtures:/fixtures:ro \
		-e KEYCLOAK_URL=http://keycloak.localhost.pomerium.io:8080 \
		-e USERS_FILE=/fixtures/users.json \
		-e RUN_ID=$(RUN_ID) \
		alpine:3.21 sh -c "apk add --no-cache curl jq bash >/dev/null 2>&1 && bash /scripts/seed-keycloak.sh seed"

# Remove test users from Keycloak (runs inside Docker network for Keycloak 26 compatibility)
cleanup-users: wait
	docker run --rm --network acceptance_acceptance \
		-v $(CURDIR)/scripts:/scripts:ro \
		-v $(CURDIR)/fixtures:/fixtures:ro \
		-e KEYCLOAK_URL=http://keycloak.localhost.pomerium.io:8080 \
		-e USERS_FILE=/fixtures/users.json \
		-e RUN_ID=$(RUN_ID) \
		alpine:3.21 sh -c "apk add --no-cache curl jq bash >/dev/null 2>&1 && bash /scripts/seed-keycloak.sh cleanup"

# Run tests (headless) — suite selected by SUITE variable
test: up seed
	cd $(BROWSER_DIR) && npm run $(NPM_TEST_SCRIPT)

# Run tests with browser visible
test-mode-headed: up seed
	cd $(BROWSER_DIR) && npm run test:headed

# Run tests in debug mode
test-mode-debug: up seed
	cd $(BROWSER_DIR) && npm run test:debug

# Run specific test suites
test-suite-authn: up seed
	cd $(BROWSER_DIR) && npm run test:authn

test-suite-authz: up seed
	cd $(BROWSER_DIR) && npm run test:authz

test-suite-headers: up seed
	cd $(BROWSER_DIR) && npm run test:headers

# Backward-compatible aliases
test-headed: test-mode-headed
test-debug: test-mode-debug
test-authn: test-suite-authn
test-authz: test-suite-authz
test-headers: test-suite-headers

# Run tests via Go test wrapper
test-go: up seed
	go test -tags=acceptance -v -timeout=20m ./...

# View container logs
logs:
	$(COMPOSE) logs -f

# Collect test artifacts
artifacts:
	./scripts/collect-artifacts.sh

# View Playwright report
report:
	cd $(BROWSER_DIR) && npm run report

# Clean up everything
clean: down
	rm -rf $(ARTIFACTS_DIR)/*

# Check stack status
status:
	@echo "=== Container Status ==="
	$(COMPOSE) ps
	@echo ""
	@echo "=== Health Checks ==="
	@curl -sf http://keycloak.localhost.pomerium.io:8080/health/ready && echo "Keycloak: healthy" || echo "Keycloak: unhealthy"
	@curl -sfk https://authenticate.localhost.pomerium.io:8443/healthz && echo "Pomerium: healthy" || echo "Pomerium: unhealthy"
	@curl -sf http://localhost:8000/ > /dev/null && echo "Upstream: healthy" || echo "Upstream: unhealthy"
	@curl -sf http://localhost:8081/health > /dev/null && echo "WebSocket: healthy" || echo "WebSocket: unhealthy"
