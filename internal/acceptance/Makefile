# E2E Acceptance Testing Makefile

.PHONY: help deps up down test test-mode-headed test-mode-debug test-suite-authn test-suite-authz test-suite-headers test-headed test-debug test-authn test-authz test-headers test-go logs status report artifacts clean

COMPOSE_PROJECT ?= acceptance
COMPOSE_FILE ?= docker-compose.yml
BROWSER_DIR ?= browser
ARTIFACTS_DIR ?= artifacts

COMPOSE := docker compose -f $(COMPOSE_FILE) -p $(COMPOSE_PROJECT)

export COMPOSE_PROJECT_NAME := $(COMPOSE_PROJECT)

help:
	@echo "Acceptance test targets:"
	@echo "  make deps         - Install npm deps and Playwright browser"
	@echo "  make up           - Start the test stack"
	@echo "  make test              - Run all Playwright tests (headless)"
	@echo "  make test-mode-headed  - Run tests with a visible browser"
	@echo "  make test-mode-debug   - Run tests in debug mode"
	@echo "  make test-suite-authn  - Run authn tests"
	@echo "  make test-suite-authz  - Run authz tests"
	@echo "  make test-suite-headers  - Run headers tests"
	@echo "  make down         - Stop the stack"
	@echo "  make logs         - Tail container logs"
	@echo "  make status       - Show container and health status"
	@echo "  make report       - Show Playwright report"
	@echo "  make artifacts    - Collect artifacts"
	@echo "  make clean        - Stop stack and remove artifacts"
	@echo ""
	@echo "Aliases: test-headed, test-debug, test-authn, test-authz, test-headers"

# Dependencies
deps:
	cd $(BROWSER_DIR) && npm ci
	cd $(BROWSER_DIR) && npx playwright install chromium

# Start the test stack
up:
	$(COMPOSE) up -d --build --wait

# Stop the test stack
down:
	$(COMPOSE) down -v

# Run all tests (headless)
test: up
	cd $(BROWSER_DIR) && npm test

# Run tests with browser visible
test-mode-headed: up
	cd $(BROWSER_DIR) && npm run test:headed

# Run tests in debug mode
test-mode-debug: up
	cd $(BROWSER_DIR) && npm run test:debug

# Run specific test suites
test-suite-authn: up
	cd $(BROWSER_DIR) && npm run test:authn

test-suite-authz: up
	cd $(BROWSER_DIR) && npm run test:authz

test-suite-headers: up
	cd $(BROWSER_DIR) && npm run test:headers

# Backward-compatible aliases
test-headed: test-mode-headed
test-debug: test-mode-debug
test-authn: test-suite-authn
test-authz: test-suite-authz
test-headers: test-suite-headers

# Run tests via Go test wrapper
test-go: up
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
