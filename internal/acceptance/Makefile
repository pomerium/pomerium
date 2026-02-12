# E2E Acceptance Testing Makefile

.PHONY: help deps up down wait seed cleanup-users test test-mode-headed test-mode-debug test-suite-authn test-suite-authz test-suite-headers test-headed test-debug test-authn test-authz test-headers test-go logs status report artifacts clean up-mcp down-mcp test-suite-mcp test-mcp test-all

COMPOSE_PROJECT ?= acceptance
COMPOSE_FILE ?= docker-compose.yml
BROWSER_DIR ?= browser
ARTIFACTS_DIR ?= artifacts

COMPOSE := docker compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT)

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
	@echo "  make test              - Run all Playwright tests (headless)"
	@echo "  make test-mode-headed  - Run tests with a visible browser"
	@echo "  make test-mode-debug   - Run tests in debug mode"
	@echo "  make test-suite-authn  - Run authn tests"
	@echo "  make test-suite-authz  - Run authz tests"
	@echo "  make test-suite-headers  - Run headers tests"
	@echo "  make test-suite-mcp    - Run MCP transport tests"
	@echo "  make test-all          - Run ALL tests (requires MCP stack)"
	@echo "  make down         - Stop the stack"
	@echo "  make logs         - Tail container logs"
	@echo "  make status       - Show container and health status"
	@echo "  make report       - Show Playwright report"
	@echo "  make artifacts    - Collect artifacts"
	@echo "  make clean        - Stop stack and remove artifacts"
	@echo ""
	@echo "Environment: RUN_ID (default: timestamp)"
	@echo "Aliases: test-headed, test-debug, test-authn, test-authz, test-headers"

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

# Run all tests (headless)
test: up seed
	cd $(BROWSER_DIR) && npm test

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

# MCP-specific targets (isolated via Docker Compose profiles)
COMPOSE_MCP := docker compose -f $(COMPOSE_FILE) -f docker-compose.mcp.yml --profile mcp -p $(COMPOSE_PROJECT)

up-mcp:
	$(COMPOSE_MCP) up -d --build

down-mcp:
	$(COMPOSE_MCP) down -v

test-suite-mcp: up-mcp seed
	cd $(BROWSER_DIR) && MCP_URL=https://mcp.localhost.pomerium.io:8443 npx playwright test tests/mcp/

test-mcp: test-suite-mcp

# Run ALL test suites (requires MCP stack: up-mcp seed first)
test-all: up-mcp seed
	cd $(BROWSER_DIR) && MCP_URL=https://mcp.localhost.pomerium.io:8443 npx playwright test

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
