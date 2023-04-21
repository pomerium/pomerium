# Setup name variables for the package/tool
PREFIX?=$(shell pwd)

NAME := pomerium
PKG := github.com/pomerium/pomerium

BUILDDIR := ${PREFIX}/dist
BINDIR := ${PREFIX}/bin
GO111MODULE=on
CGO_ENABLED := 0
# Set any default go build tags
BUILDTAGS :=

# Populate version variables
# Add to compile time flags
VERSION := $(shell git describe --tags)
GITCOMMIT := $(shell git rev-parse --short HEAD)
BUILDMETA:=
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
ifneq ($(GITUNTRACKEDCHANGES),)
	BUILDMETA := dirty
endif
CTIMEVAR=-X $(PKG)/internal/version.GitCommit=$(GITCOMMIT) \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.BuildMeta=$(BUILDMETA) \
	-X $(PKG)/internal/version.ProjectName=$(NAME) \
	-X $(PKG)/internal/version.ProjectURL=$(PKG)

GO ?= "go"
GO_LDFLAGS=-ldflags "-s -w $(CTIMEVAR)"
GOOSARCHES = linux/amd64 darwin/amd64 windows/amd64
GOOS = $(shell $(GO) env GOOS)
GOARCH= $(shell $(GO) env GOARCH)
GETENVOY_VERSION = v0.2.0
GORELEASER_VERSION = v0.174.2

.PHONY: all
all: clean build-deps test lint build ## Runs a clean, build, fmt, lint, test, and vet.


.PHONY: generate-mocks
generate-mocks: ## Generate mocks
	@echo "==> $@"
	@go run github.com/golang/mock/mockgen -destination internal/directory/auth0/mock_auth0/mock.go github.com/pomerium/pomerium/internal/directory/auth0 RoleManager


.PHONY: deps-release
deps-release: ## Install release dependencies
	@echo "==> $@"
	#@cd /tmp; GO111MODULE=on $(GO) install github.com/goreleaser/goreleaser@${GORELEASER_VERSION}

.PHONY: tag
tag: ## Create a new git tag to prepare to build a release
	git tag -sa $(VERSION) -m "$(VERSION)"
	@echo "Run git push origin $(VERSION) to push your new tag to GitHub."

.PHONY: proto
proto:
	@echo "==> $@"
	cd pkg/grpc && ./protoc.bash

.PHONY: build
build: build-ui build-go
	@echo "==> $@"

.PHONY: build-debug
build-debug: ## Builds binaries appropriate for debugging
	@echo "==> $@"
	@CGO_ENABLED=0 GO111MODULE=on bazel build //:pomerium -c dbg

.PHONY: build-go
build-go:
	@echo "==> $@"
	@CGO_ENABLED=0 GO111MODULE=on bazel build //:pomerium
	
.PHONY: build-ui
build-ui: yarn
	@echo "==> $@"
	@cd ui; yarn build

.PHONY: lint
lint: ## Verifies `golint` passes.
	@echo "==> $@"
	@$(GO) run github.com/golangci/golangci-lint/cmd/golangci-lint run ./...

.PHONY: test
test:  ## Runs the go tests.
	@echo "==> $@"
	@$(GO) test -race -tags "$(BUILDTAGS)" $(shell $(GO) list ./... | grep -v vendor | grep -v github.com/pomerium/pomerium/integration)

.PHONY: cover
cover:  ## Runs go test with coverage
	@echo "==> $@"
	$(GO) test -race -coverprofile=coverage.txt -tags "$(BUILDTAGS)" $(shell $(GO) list ./... | grep -v vendor | grep -v github.com/pomerium/pomerium/integration)
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
	cd ui ; yarn install --network-timeout 120000

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
