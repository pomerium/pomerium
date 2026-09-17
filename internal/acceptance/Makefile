# E2E Acceptance Testing Makefile

.PHONY: help deps up down test test-mode-headed test-mode-debug test-suite-authn test-suite-authz test-suite-headers up-hosted test-suite-hosted test-hosted test-headed test-debug test-authn test-authz test-headers test-go logs status report artifacts clean deps-mcp test-mcp test-mcp-headed deps-downstream-mtls test-downstream-mtls test-downstream-mtls-headed deps-upstream-tls test-upstream-tls test-upstream-tls-headed

COMPOSE_PROJECT ?= acceptance
COMPOSE_FILE ?= docker-compose.yml
BROWSER_DIR ?= browser
MCP_DIR ?= suites/mcp
DOWNSTREAM_MTLS_DIR ?= suites/downstream-mtls
UPSTREAM_TLS_DIR ?= suites/upstream-tls
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
	@echo "  make test-suite-hosted   - Run hosted-authenticate tests (real cloud;"
	@echo "                             needs internet + optional HOSTED_TEST_EMAIL/PASSWORD)"
	@echo "  make up-hosted    - Start the stack incl. hosted-authenticate instances"
	@echo "  make down         - Stop the stack"
	@echo "  make logs         - Tail container logs"
	@echo "  make status       - Show container and health status"
	@echo "  make report       - Show Playwright report"
	@echo "  make artifacts    - Collect artifacts"
	@echo "  make clean        - Stop stack and remove artifacts"
	@echo ""
	@echo "MCP suite (testcontainers, self-contained - does NOT use the compose stack):"
	@echo "  make deps-mcp        - Install MCP suite deps + Chromium"
	@echo "  make test-mcp        - Run the container-based MCP e2e suite (headless)"
	@echo "  make test-mcp-headed - Run the MCP e2e suite with a visible browser"
	@echo ""
	@echo "Downstream mTLS suite (testcontainers, self-contained - does NOT use the compose stack):"
	@echo "  make deps-downstream-mtls        - Install suite deps + Chromium, refresh pomerium image"
	@echo "  make test-downstream-mtls        - Run the downstream mTLS e2e suite (headless)"
	@echo "  make test-downstream-mtls-headed - Run it with a visible browser"
	@echo ""
	@echo "Upstream TLS suite (testcontainers, self-contained - does NOT use the compose stack):"
	@echo "  make deps-upstream-tls        - Install suite deps + Chromium, refresh pomerium image"
	@echo "  make test-upstream-tls        - Run the upstream TLS/mTLS e2e suite (headless)"
	@echo "  make test-upstream-tls-headed - Run it with a visible browser"
	@echo ""
	@echo "Aliases: test-headed, test-debug, test-authn, test-authz, test-headers"

# Dependencies
deps:
	cd $(BROWSER_DIR) && npm ci
	cd $(BROWSER_DIR) && npx playwright install chromium

# Start the test stack
up:
	$(COMPOSE) up -d --build --wait

# Stop the test stack (includes the "hosted" profile services, if started)
down:
	$(COMPOSE) --profile hosted down -v

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

# Start the test stack INCLUDING the hosted-authenticate instances
up-hosted:
	$(COMPOSE) --profile hosted up -d --build --wait

# Hosted-authenticate suite: talks to the REAL https://authenticate.pomerium.app
# (requires outbound internet). Positive login/logout/timeout tests additionally
# need HOSTED_TEST_EMAIL and HOSTED_TEST_PASSWORD (a real hosted-IdP account)
# exported in the environment; without them those tests are skipped.
test-suite-hosted: up-hosted
	cd $(BROWSER_DIR) && HOSTED_E2E=1 npm run test:hosted

# Backward-compatible aliases
test-headed: test-mode-headed
test-debug: test-mode-debug
test-authn: test-suite-authn
test-authz: test-suite-authz
test-headers: test-suite-headers
test-hosted: test-suite-hosted

# Run tests via Go test wrapper
test-go: up
	go test -tags=acceptance -v -timeout=20m ./...

# ---------------------------------------------------------------------------
# Downstream mTLS e2e suite (internal/acceptance/suites/downstream-mtls):
# testcontainers-based and entirely self-contained - it boots its own Keycloak
# + upstream + Pomerium (official image) and does NOT use the compose stack
# above. Do not run `make up` and `make test-downstream-mtls` at the same
# time: both bind host ports 8443/8080.
# ---------------------------------------------------------------------------
deps-downstream-mtls:
	$(MAKE) -C $(DOWNSTREAM_MTLS_DIR) deps

test-downstream-mtls:
	$(MAKE) -C $(DOWNSTREAM_MTLS_DIR) test

test-downstream-mtls-headed:
	$(MAKE) -C $(DOWNSTREAM_MTLS_DIR) test-headed

# ---------------------------------------------------------------------------
# Upstream TLS/mTLS e2e suite (internal/acceptance/suites/upstream-tls):
# testcontainers-based and entirely self-contained - it boots its own Keycloak
# + upstreams (verify + Node TLS/mTLS echo servers) + Pomerium (official image)
# and does NOT use the compose stack above. Do not run `make up` and
# `make test-upstream-tls` at the same time: both bind host ports 8443/8080.
# ---------------------------------------------------------------------------
deps-upstream-tls:
	$(MAKE) -C $(UPSTREAM_TLS_DIR) deps

test-upstream-tls:
	$(MAKE) -C $(UPSTREAM_TLS_DIR) test

test-upstream-tls-headed:
	$(MAKE) -C $(UPSTREAM_TLS_DIR) test-headed

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

# ---------------------------------------------------------------------------
# MCP e2e suite (internal/acceptance/mcp): testcontainers-based and entirely
# self-contained - it boots its own Keycloak + upstream + Pomerium and does NOT
# use the compose stack above. Do not run `make up` and `make test-mcp` at the
# same time: both bind host ports 8443/8080.
# ---------------------------------------------------------------------------
deps-mcp:
	$(MAKE) -C $(MCP_DIR) deps

test-mcp:
	$(MAKE) -C $(MCP_DIR) test

test-mcp-headed:
	$(MAKE) -C $(MCP_DIR) test-headed
