# OpenID Foundation conformance suite (OIDC Basic OP + Config OP plans) against
# Pomerium's OIDC bridge. testcontainers + real Keycloak + Playwright.
#
# Pomerium is built from this source tree (the bridge is not in a published
# image). Set POMERIUM_IMAGE to an existing image and BUILD_IMAGE=0 to skip the
# build.

.PHONY: help deps image test test-headed test-keep down clean

REPO_ROOT := $(abspath ../../../..)
export POMERIUM_IMAGE ?= pomerium-oidc-conformance:local
BUILD_IMAGE ?= 1
# Created by the global setup (setup/certs.ts).
CERTS_DIR := .certs

help:
	@echo "OIDC conformance e2e targets:"
	@echo "  make deps         - npm ci + install Playwright Chromium"
	@echo "  make image        - build $(POMERIUM_IMAGE) from this source tree"
	@echo "  make test         - build the image, then run the conformance plans headless"
	@echo "  make test-headed  - same, with a visible browser"
	@echo "  make test-keep    - same, but leave the containers running afterwards"
	@echo "                      (suite UI/logs at http://127.0.0.1:18080)"
	@echo "  make down         - remove containers left running by test-keep"
	@echo "  make clean        - remove generated certs and test artifacts"

deps:
	cd .. && npm ci
	npx playwright install chromium

image:
ifeq ($(BUILD_IMAGE),1)
	docker build -t $(POMERIUM_IMAGE) $(REPO_ROOT)
endif

test: image
	npx playwright test

test-headed: image
	npx playwright test --headed

# Ryuk would reap the containers when the runner exits, so disable it too.
test-keep: image
	OIDC_CONFORMANCE_KEEP=1 TESTCONTAINERS_RYUK_DISABLED=true npx playwright test

down:
	-docker rm -f $$(docker ps -aq --filter label=io.pomerium.e2e=oidc-conformance) 2>/dev/null
	-docker network prune -f --filter label=org.testcontainers=true >/dev/null

clean: down
	rm -rf $(CERTS_DIR) test-results playwright-report results.json oidc-conformance-report.md
