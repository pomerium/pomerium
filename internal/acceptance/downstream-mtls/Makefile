# Container-based Pomerium downstream mTLS e2e suite.
# testcontainers + real Keycloak + Playwright browser sign-in with client
# certificates, against the official pomerium/pomerium container.

.PHONY: help deps test test-headed test-debug clean

export POMERIUM_IMAGE ?= pomerium/pomerium:main

help:
	@echo "Pomerium downstream mTLS e2e targets:"
	@echo "  make deps         - npm ci + install Playwright Chromium + refresh $(POMERIUM_IMAGE)"
	@echo "  make test         - run the suite headless (boots & tears down containers)"
	@echo "  make test-headed  - run with a visible browser"
	@echo "  make test-debug   - run with the Playwright inspector"
	@echo "  make clean        - remove generated certs and test artifacts"

# testcontainers only pulls images that are missing locally, so `deps` also
# refreshes the rolling pomerium tag.
deps:
	npm ci
	npx playwright install chromium
	docker pull $(POMERIUM_IMAGE)

test:
	npx playwright test

test-headed:
	npx playwright test --headed

test-debug:
	npx playwright test --debug

clean:
	rm -rf .certs test-results playwright-report
