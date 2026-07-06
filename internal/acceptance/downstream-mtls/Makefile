# E2E test suite for Pomerium downstream mTLS.
# Host prerequisites: Docker + Go (plus Node.js 22+ for headed/host mode).

# Image knobs, exported so `make test POMERIUM_IMAGE=...` reaches go test.
# PLAYWRIGHT_IMAGE must match the exact @playwright/test version pinned in
# browser/package.json - bump them together (then run `make lockfile`).
export POMERIUM_IMAGE ?= pomerium/pomerium:main
export KEYCLOAK_IMAGE ?= quay.io/keycloak/keycloak:26.5.2
export UPSTREAM_IMAGE ?= traefik/whoami:v1.11
export PLAYWRIGHT_IMAGE ?= mcr.microsoft.com/playwright:v1.61.1-noble
CERTGEN_IMAGE ?= alpine:3.21

GOTEST := go test -tags e2e -v -timeout 30m ./...

.PHONY: help deps test test-host test-headed lockfile clean

help:
	@echo "Downstream mTLS e2e targets:"
	@echo "  make deps         - Pull Docker images (refreshes $(POMERIUM_IMAGE)); install host browser deps for headed mode"
	@echo "  make test         - Run the suite (Playwright in a container)"
	@echo "  make test-host    - Run with Playwright on the host (headless; needs Node.js)"
	@echo "  make test-headed  - Run with a visible browser on the host (needs Node.js)"
	@echo "  make lockfile     - Regenerate browser/package-lock.json (dockerized npm)"
	@echo "  make clean        - Remove per-run artifacts"

# Pre-pull all images. This also refreshes the rolling pomerium tag - the
# test itself only pulls images that are missing locally.
deps:
	docker pull $(CERTGEN_IMAGE)
	docker pull $(KEYCLOAK_IMAGE)
	docker pull $(UPSTREAM_IMAGE)
	docker pull $(POMERIUM_IMAGE)
	docker pull $(PLAYWRIGHT_IMAGE)
	@if command -v npm >/dev/null 2>&1; then \
		cd browser && npm ci --no-audit --no-fund && npx playwright install chromium; \
	else \
		echo "npm not found - skipped host browser deps (only needed for test-headed/test-host)"; \
	fi

test:
	$(GOTEST)

test-host:
	E2E_PLAYWRIGHT_MODE=host $(GOTEST)

test-headed:
	E2E_HEADED=1 $(GOTEST)

# Regenerate browser/package-lock.json without requiring node/npm on the host.
lockfile:
	docker run --rm -v $(CURDIR)/browser:/work -w /work $(PLAYWRIGHT_IMAGE) \
		sh -c "npm install --package-lock-only --no-audit --no-fund && chmod a+rw package-lock.json"

clean:
	rm -rf artifacts/run-*
