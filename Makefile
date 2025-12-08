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
GORELEASER_VERSION = v0.174.2
GO_TESTFLAGS := -race
# disable the race detector in macos
ifeq ($(shell env -u GOOS $(GO) env GOOS), darwin)
	GO_TESTFLAGS :=
endif

.PHONY: all
all: clean build-deps test lint build ## Runs a clean, build, fmt, lint, test, and vet.

.PHONY: check-component-versions
check-component-versions:
	@echo "==> $@"
	@scripts/check-component-versions

.PHONY: get-envoy
get-envoy: ## Fetch envoy binaries
	@echo "==> $@"
	@cd pkg/envoy/files && env -u GOOS $(GO) run ../get-envoy

.PHONY: deps-build
deps-build: get-envoy ## Install build dependencies
	@echo "==> $@"

.PHONY: deps-release
deps-release: get-envoy ## Install release dependencies
	@echo "==> $@"
	@cd /tmp; $(GO) install github.com/goreleaser/goreleaser@${GORELEASER_VERSION}

.PHONY: build-deps
build-deps: deps-build deps-release
	@echo "==> $@"

.PHONY: proto
proto:
	@echo "==> $@"
	cd pkg/grpc && ./protoc.bash

.PHONY: generate
generate: proto
	@echo "==> $@"
	$(GO) generate ./...

.PHONY: build
build: build-ui build-go
	@echo "==> $@"

.PHONY: build-debug
build-debug: build-deps ## Builds binaries appropriate for debugging
	@echo "==> $@"
	@CGO_ENABLED=0 $(GO) build -gcflags="all=-N -l" -o $(BINDIR)/$(NAME) ./cmd/"$(NAME)"

.PHONY: build-go
build-go: build-deps
	@echo "==> $@"
	@CGO_ENABLED=0 $(GO) build -tags "$(BUILDTAGS)" ${GO_LDFLAGS} -o $(BINDIR)/$(NAME) ./cmd/"$(NAME)"

.PHONY: build-ui
build-ui: npm-install
	@echo "==> $@"
	@cd ui; npm run build

.PHONY: lint
lint: install-lint
	@echo "@==> $@"
	./bin/golangci-lint run ./... --fix --timeout=10m

.PHONY: install-lint
install-lint:
	@echo "@==> $@"
	./scripts/install-lint.sh

.PHONY: test
test: get-envoy ## Runs the go tests.
	@echo "==> $@"
	$(GO) test $(GO_TESTFLAGS) -tags "$(BUILDTAGS)" ./...

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
snapshot: build-deps ## Builds the cross-compiled binaries, naming them in such a way for release (eg. binary-GOOS-GOARCH)
	@echo "==> $@"
	@goreleaser release --rm-dist -f .github/goreleaser.yaml --snapshot

.PHONY: npm-install
npm-install:
	@echo "==> $@"
	cd ui ; npm install

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
