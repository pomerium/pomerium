# E2E test suite for Pomerium downstream mTLS.
# Host prerequisites: Docker + Go. Everything else runs in containers.

# Must match the exact @playwright/test version pinned in browser/package.json.
PLAYWRIGHT_IMAGE ?= mcr.microsoft.com/playwright:v1.61.1-noble

.PHONY: test lockfile clean

test:
	go test -tags e2e -v -timeout 30m ./...

# Regenerate browser/package-lock.json without requiring node/npm on the host.
lockfile:
	docker run --rm -v $(CURDIR)/browser:/work -w /work $(PLAYWRIGHT_IMAGE) \
		sh -c "npm install --package-lock-only --no-audit --no-fund && chmod a+rw package-lock.json"

clean:
	rm -rf artifacts/run-*
