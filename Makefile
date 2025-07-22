# Setup name variables for the package/tool
PREFIX?=$(shell pwd)

NAME := pomerium
PKG := github.com/pomerium/pomerium

BUILDDIR := ${PREFIX}/dist
BINDIR := ${PREFIX}/bin
export GOEXPERIMENT=synctest
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

.PHONY: get-envoy
get-envoy: ## Fetch envoy binaries
	@echo "==> $@"
	@cd pkg/envoy/files && env -u GOOS $(GO) run ../get-envoy


.PHONY: deps-release
deps-release: get-envoy ## Install release dependencies
	@echo "==> $@"
	@cd /tmp; $(GO) install github.com/goreleaser/goreleaser@${GORELEASER_VERSION}

.PHONY: build-deps
build-deps: deps-release
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
build-ui: yarn
	@echo "==> $@"
	@cd ui; yarn build

.PHONY: lint
lint:
	@echo "@==> $@"
	@VERSION=$$(go run github.com/mikefarah/yq/v4@v4.34.1 '.jobs.lint.steps[] | select(.uses == "golangci/golangci-lint-action*") | .with.version' .github/workflows/lint.yaml) && \
	$(GO) run github.com/golangci/golangci-lint/cmd/golangci-lint@$$VERSION run ./... --fix

.PHONY: test
test: get-envoy ## Runs the go tests.
	@echo "==> $@"
	$(GO) test $(GO_TESTFLAGS) -tags "$(BUILDTAGS)" ./...

.PHONY: cover
cover: get-envoy ## Runs go test with coverage
	@echo "==> $@"
	$(GO) test $(GO_TESTFLAGS) -tags "$(BUILDTAGS)" -coverprofile=coverage.txt ./...
	@sed -i.bak '/\.pb\.go\:/d' coverage.txt
	@sed -i.bak '/\/mock\.go\:/d' coverage.txt
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

.PHONY: yarn
yarn:
	@echo "==> $@"
	cd ui ; yarn install --network-timeout 120000 --frozen-lockfile

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
