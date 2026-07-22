# Setup name variables for the package/tool
PREFIX?=$(shell pwd)

NAME := pomerium
PKG := github.com/pomerium/pomerium

BUILDDIR := ${PREFIX}/dist
BINDIR := ${PREFIX}/bin
# Set any default go build tags
BUILDTAGS :=

# Populate version variables
# Add to compile time flags
VERSION ?= $(shell git describe --tags)
GITCOMMIT := $(shell git rev-parse --short HEAD)
BUILDMETA :=
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GITUNTRACKEDCHANGES),)
	BUILDMETA := dirty
endif
CTIMEVAR = \
	-X $(PKG)/internal/version.GitCommit=$(GITCOMMIT) \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.BuildMeta=$(BUILDMETA) \
	-X $(PKG)/internal/version.ProjectName=$(NAME) \
	-X $(PKG)/internal/version.ProjectURL=$(PKG)

GO ?= "go"
GO_LDFLAGS = -ldflags "-s -w $(CTIMEVAR)"
GOOS = $(shell $(GO) env GOOS)
GOARCH = $(shell $(GO) env GOARCH)
GORELEASER_VERSION = v$(shell grep '^goreleaser ' .tool-versions | awk '{print $$2}')
GO_TESTFLAGS := -race
# disable the race detector in macos
ifeq ($(shell env -u GOOS $(GO) env GOOS), darwin)
	GO_TESTFLAGS :=
	export POMERIUM_SOCKET_DIRECTORY := /tmp
endif
ENVOY_OCI_REPO ?= "ghcr.io/pomerium/envoy-custom"
GET_ENVOY_DEBUG :=

.PHONY: all
all: clean deps-build test lint build ## Runs a clean, build, fmt, lint, test, and vet.

.PHONY: setup-merge-driver
setup-merge-driver: ## Configure git merge driver for components.json (run once after cloning)
	@echo "==> $@"
	@git config merge.components-json.driver 'scripts/merge-components-json %O %A %B'
	@git config merge.components-json.name 'Merge components.json by picking highest semver'
	@echo "Git merge driver configured for internal/version/components.json"

.PHONY: check-component-versions
check-component-versions:
	@echo "==> $@"
	@scripts/check-component-versions

.PHONY: get-envoy
get-envoy: ## Fetch envoy binaries
	@echo "==> $@"
	@cd pkg/envoy/files && env -u GOOS -u GOARCH $(GO) run ../get-envoy --repo $(ENVOY_OCI_REPO) $(if $(GET_ENVOY_DEBUG),--debug,)

.PHONY: deps-build
deps-build: get-envoy ## Install build dependencies
	@echo "==> $@"

.PHONY: deps-release
deps-release: get-envoy ## Install release dependencies
	@echo "==> $@"
	@$(GO) install github.com/goreleaser/goreleaser/v2@${GORELEASER_VERSION}

.PHONY: proto-before
proto-before:
	@echo "==> $@"
	cd pkg/grpc && ./protoc.bash

.PHONY: proto-after
proto-after: generate-code
	@echo "==> $@"

.PHONY: proto
proto: proto-before proto-after
	@echo "==> $@"

.PHONY: generate
generate: proto
	@echo "==> $@"
	$(GO) generate ./...

.PHONY: generate-code
generate-code:
	@echo "==> $@"
	$(GO) run ./internal/generate

.PHONY: build
build: build-ui build-go
	@echo "==> $@"

.PHONY: build-debug
build-debug: deps-build ## Builds binaries appropriate for debugging
	@echo "==> $@"
	@CGO_ENABLED=0 $(GO) build -gcflags="all=-N -l" -o $(BINDIR)/$(NAME) ./cmd/"$(NAME)"

.PHONY: build-go
build-go: deps-build
	@echo "==> $@"
	@CGO_ENABLED=0 $(GO) build -tags "$(BUILDTAGS)" ${GO_LDFLAGS} -o $(BINDIR)/$(NAME) ./cmd/"$(NAME)"

DEBUG_LOCAL_ENVOY_PATH ?=
build-local: build-ui # Builds pomerium core with a local envoy build
	@echo "==> $@"
	@echo "${DEBUG_LOCAL_ENVOY_PATH}"
	@CGO_ENABLED=0 $(GO) build -tags "debug_local_envoy $(BUILDTAGS)" -ldflags "-s -w $(CTIMEVAR) -X $(PKG)/pkg/envoy.DebugLocalEnvoyPath=$(DEBUG_LOCAL_ENVOY_PATH)" -o $(BINDIR)/$(NAME) ./cmd/"$(NAME)"

.PHONY: build-ui
build-ui: npm-install
	@echo "==> $@"
	@cd ui; npm run build

.PHONY: go-fix
go-fix: deps-build
	@echo "==> $@"
	$(GO) fix ./...

.PHONY: docker
docker: build-ui ## Builds the local root image through the release Dockerfile.
	@echo "==> $@"
	@set -eu; \
		_temp_dir="$$(mktemp -d "$${TMPDIR:-/tmp}/pomerium-debug.XXXXXX")"; \
		trap 'rm -rf "$$_temp_dir"' EXIT INT TERM; \
		GOOS=linux $(MAKE) build-go; \
		cp "$(BINDIR)/$(NAME)" "$$_temp_dir/pomerium"; \
		docker build -t pomerium/pomerium:local -f .github/Dockerfile-release "$$_temp_dir"

.PHONY: docker-debug
docker-debug: build-ui ## Builds the local root debug image through the release debug Dockerfile.
	@echo "==> $@"
	@set -eu; \
		_temp_dir="$$(mktemp -d "$${TMPDIR:-/tmp}/pomerium-debug.XXXXXX")"; \
		trap 'rm -rf "$$_temp_dir"' EXIT INT TERM; \
		GOOS=linux $(MAKE) build-go; \
		cp "$(BINDIR)/$(NAME)" "$$_temp_dir/pomerium"; \
		docker build -t pomerium/pomerium:debug-local -f .github/Dockerfile-release-debug "$$_temp_dir"

.PHONY: lint
lint:
	@echo "==> $@"
	$(GO) run ./pkg/tools/get-tools.go && \
	./bin/golangci-lint run --fix --timeout=10m ./...

.PHONY: govulncheck
govulncheck: ## Scan for known Go vulnerabilities (all workspace modules)
	@echo "==> $@"
	@for dir in $$($(GO) list -m -f '{{.Dir}}'); do \
		echo "==> govulncheck $$dir"; \
		( cd "$$dir" && $(GO) run golang.org/x/vuln/cmd/govulncheck@v1.5.0 ./... ) || exit 1; \
	done

.PHONY: test
test: get-envoy ## Runs the go tests.
	@echo "==> $@"
	$(GO) test $(GO_TESTFLAGS) -tags "$(BUILDTAGS)" ./...

BENCH ?= BenchmarkGetMatchingPolicy|BenchmarkWithQuerierForCheckRequest|BenchmarkStoreGetDataBrokerRecord|BenchmarkCachingQuerier|BenchmarkEvaluate$$|BenchmarkHeadersEvaluator|BenchmarkPolicyChecksum|BenchmarkBuildRouteConfigurations|BenchmarkGetAllRouteableHTTPHosts|BenchmarkDiscoveryResourceEncoding
BENCH_PKGS ?= ./authorize ./authorize/internal/store ./authorize/evaluator ./pkg/storage ./config ./config/envoyconfig ./internal/controlplane
BENCH_COUNT ?= 10
BENCH_BASELINE ?= internal/benchmarks/baseline.txt
BENCHSTAT ?= golang.org/x/perf/cmd/benchstat@v0.0.0-20260709024250-82a0b07e230d

# Benchmarks run without -race on every platform and with -short, which skips
# the slowest route-scaling cases (drop -short for ad-hoc quadratic runs).
# benchstat deltas are only meaningful against a baseline generated on
# the same machine: regenerate with `make bench-baseline` before comparing.
# -p=1 serializes package benchmark binaries so they don't compete for CPU.
# A failed `go test` is printed and aborts before truncated output can reach
# benchstat (or replace the committed baseline).
.PHONY: bench
bench: ## Runs hot-path benchmarks and compares against the committed baseline
	@echo "==> $@"
	@tmp="$$(mktemp "$${TMPDIR:-/tmp}/pomerium-bench-new.XXXXXX")"; trap 'rm -f "$$tmp"' EXIT; \
		if [ ! -r "$(BENCH_BASELINE)" ]; then \
			echo "benchmark baseline is not readable: $(BENCH_BASELINE)"; \
			exit 1; \
		fi; \
		if ! $(GO) test -p=1 -run '^$$' -short -tags "$(BUILDTAGS)" -bench '$(BENCH)' -benchmem -count $(BENCH_COUNT) -timeout 60m $(BENCH_PKGS) > "$$tmp"; then \
			cat "$$tmp"; \
			exit 1; \
		fi; \
		if ! $(GO) run $(BENCHSTAT) "$(BENCH_BASELINE)" "$$tmp"; then \
			echo "benchmark output preserved at $$tmp"; \
			trap - EXIT; \
			exit 1; \
		fi

.PHONY: bench-baseline
bench-baseline: ## Regenerates the committed benchmark baseline (same-machine reference)
	@echo "==> $@"
	@tmp="$$(mktemp "$(BENCH_BASELINE).tmp.XXXXXX")"; trap 'rm -f "$$tmp"' EXIT; \
		if ! $(GO) test -p=1 -run '^$$' -short -tags "$(BUILDTAGS)" -bench '$(BENCH)' -benchmem -count $(BENCH_COUNT) -timeout 60m $(BENCH_PKGS) > "$$tmp"; then \
			cat "$$tmp"; \
			exit 1; \
		fi; \
		mv "$$tmp" "$(BENCH_BASELINE)"

.PHONY: cover
cover: get-envoy ## Runs go test with coverage
	@echo "==> $@"
	$(GO) test $(GO_TESTFLAGS) -tags "$(BUILDTAGS)" -coverprofile=coverage.txt ./...
	@sed -i.bak '/\.pb\.go\:/d' coverage.txt
	@sed -i.bak '/\/mock_.*\.go\:/d' coverage.txt
	@sed -i.bak '/\.gen\.go\:/d' coverage.txt
	@sed -i.bak '/\/internal\/testenv\/:/d' coverage.txt
	@sed -i.bak '/\/internal\/testutil\/:/d' coverage.txt
	@sed -i.bak '/\/internal\/tests\/:/d' coverage.txt
	@sed -i.bak '/\/storagetest\/:/d' coverage.txt
	@sed -i.bak '/\/integration\/:/d' coverage.txt
	@sed -i.bak '/\/examples\/:/d' coverage.txt
	@sed -i.bak '/\/ssh\/test\/:/d' coverage.txt
	@sort -o coverage.txt coverage.txt

.PHONY: clean
clean: ## Cleanup any build binaries or packages.
	@echo "==> $@"
	$(RM) -r $(BINDIR)
	$(RM) -r $(BUILDDIR)
	$(RM) pkg/envoy/files/envoy-*
	$(RM) $(GOPATH)/bin/protoc-gen-validate
	$(RM) -r /tmp/pomerium-protoc
	$(RM) -r /tmp/pomerium-protoc-3pp

.PHONY: snapshot
snapshot: deps-build deps-release ## Builds the cross-compiled binaries, naming them in such a way for release (eg. binary-GOOS-GOARCH)
	@echo "==> $@"
	@goreleaser release --clean -f .github/goreleaser.yaml --snapshot

.PHONY: npm-install
npm-install:
	@echo "==> $@"
	cd ui ; npm ci

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
