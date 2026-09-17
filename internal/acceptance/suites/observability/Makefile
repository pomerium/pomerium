# Container-based Pomerium observability e2e suite: access/authorize logging,
# the Prometheus metrics endpoint, and OTEL tracing against a real Jaeger
# collector — testcontainers + real Keycloak + Playwright, against the official
# pomerium/pomerium container.

.PHONY: help deps test test-headed test-debug clean

export POMERIUM_IMAGE ?= pomerium/pomerium:main

help:
	@echo "Pomerium observability e2e targets:"
	@echo "  make deps         - npm ci + install Playwright Chromium + refresh $(POMERIUM_IMAGE)"
	@echo "  make test         - run the suite headless (boots & tears down containers)"
	@echo "  make test-headed  - run with a visible browser"
	@echo "  make test-debug   - run with the Playwright inspector"
	@echo "  make clean        - remove generated certs, configs and test artifacts"
	@echo ""
	@echo "Requires mkcert on the host (brew install mkcert); no 'mkcert -install' needed."
	@echo "Binds fixed host ports 8443, 8080, 9902 and 16686 - do not run alongside"
	@echo "'make up' or the other container suites."

# testcontainers only pulls images that are missing locally, so `deps` also
# refreshes the rolling pomerium tag.
deps:
	cd .. && npm ci
	npx playwright install chromium
	docker pull $(POMERIUM_IMAGE)

test:
	npx playwright test

test-headed:
	npx playwright test --headed

test-debug:
	npx playwright test --debug

clean:
	rm -rf .certs .gen test-results playwright-report results.json
