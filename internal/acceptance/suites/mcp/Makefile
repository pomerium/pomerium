# Container-based Pomerium MCP e2e suite.
# testcontainers + real Keycloak + Playwright browser sign-in + the official MCP
# TypeScript SDK client, against the official pomerium/pomerium container.

.PHONY: help deps certs test test-headed test-debug clean

CERTS_DIR := .certs
SANS := "*.localhost.pomerium.io" localhost.pomerium.io localhost 127.0.0.1
CAROOT := $(shell mkcert -CAROOT 2>/dev/null)
# Trust the mkcert root CA in the MCP client's HTTPS calls to Pomerium. The path
# contains a space on macOS, so it must stay quoted at the point of use.
NODE_CA := NODE_EXTRA_CA_CERTS="$(CAROOT)/rootCA.pem"

help:
	@echo "Pomerium MCP e2e targets:"
	@echo "  make deps         - npm ci + install Playwright Chromium"
	@echo "  make certs        - generate the mkcert wildcard leaf certificate"
	@echo "  make test         - run the suite headless (boots & tears down containers)"
	@echo "  make test-headed  - run with a visible browser"
	@echo "  make test-debug   - run with the Playwright inspector"
	@echo "  make clean        - remove generated certs and test artifacts"

deps:
	npm ci
	npx playwright install chromium

# Generate the leaf cert (creates the local mkcert CA if it does not exist yet).
certs:
	@mkdir -p $(CERTS_DIR)
	@test -f $(CERTS_DIR)/pomerium.crt || \
		mkcert -cert-file $(CERTS_DIR)/pomerium.crt -key-file $(CERTS_DIR)/pomerium.key $(SANS)

test: certs
	$(NODE_CA) npx playwright test

test-headed: certs
	$(NODE_CA) npx playwright test --headed

test-debug: certs
	$(NODE_CA) npx playwright test --debug

clean:
	rm -rf $(CERTS_DIR) test-results playwright-report results.json
