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
MISSPELL_VERSION = v0.3.4
GOLANGCI_VERSION = v1.34.1
OPA_VERSION = v0.25.2
GETENVOY_VERSION = v0.2.0
GORELEASER_VERSION = v0.150.0

.PHONY: all
all: clean build-deps test lint spellcheck build ## Runs a clean, build, fmt, lint, test, and vet.


.PHONY: generate-mocks
generate-mocks: ## Generate mocks
	@echo "==> $@"
	@go run github.com/golang/mock/mockgen -destination internal/directory/auth0/mock_auth0/mock.go github.com/pomerium/pomerium/internal/directory/auth0 RoleManager

.PHONY: build-deps
build-deps: ## Install build dependencies
	@echo "==> $@"
	@cd /tmp; GO111MODULE=on $(GO) get github.com/client9/misspell/cmd/misspell@${MISSPELL_VERSION}
	@cd /tmp; GO111MODULE=on $(GO) get github.com/golangci/golangci-lint/cmd/golangci-lint@${GOLANGCI_VERSION}
	@cd /tmp; GO111MODULE=on $(GO) get github.com/open-policy-agent/opa@${OPA_VERSION}
	@cd /tmp; GO111MODULE=on $(GO) get github.com/tetratelabs/getenvoy/cmd/getenvoy@${GETENVOY_VERSION}
	@cd /tmp; GO111MODULE=on $(GO) get github.com/goreleaser/goreleaser@${GORELEASER_VERSION}

.PHONY: docs
docs: ## Start the vuepress docs development server
	@echo "==> $@"
	@yarn && yarn docs:dev

.PHONY: tag
tag: ## Create a new git tag to prepare to build a release
	git tag -sa $(VERSION) -m "$(VERSION)"
	@echo "Run git push origin $(VERSION) to push your new tag to GitHub."

.PHONY: frontend
frontend: ## Runs go generate on the static assets package.
	@echo "==> $@"
	@CGO_ENABLED=0 GO111MODULE=on $(GO) generate github.com/pomerium/pomerium/internal/frontend

.PHONY: build
build: ## Builds dynamic executables and/or packages.
	@echo "==> $@"
	@CGO_ENABLED=0 GO111MODULE=on $(GO) build -tags "$(BUILDTAGS)" ${GO_LDFLAGS} -o $(BINDIR)/$(NAME) ./cmd/"$(NAME)"
	./scripts/embed-envoy.bash $(BINDIR)/$(NAME)

.PHONY: build-debug
build-debug: ## Builds binaries appropriate for debugging
	@echo "==> $@"
	@CGO_ENABLED=0 GO111MODULE=on $(GO) build -gcflags="all=-N -l" -o $(BINDIR)/$(NAME) ./cmd/"$(NAME)"
	./scripts/embed-envoy.bash $(BINDIR)/$(NAME)


.PHONY: lint
lint: ## Verifies `golint` passes.
	@echo "==> $@"
	@golangci-lint run ./...

.PHONY: test
test: ## Runs the go tests.
	@echo "==> $@"
	@$(GO) test -tags "$(BUILDTAGS)" $(shell $(GO) list ./... | grep -v vendor | grep -v github.com/pomerium/pomerium/integration)
	@opa test ./authorize/evaluator/opa/policy

.PHONY: spellcheck
spellcheck: # Spellcheck docs
	@echo "==> Spell checking docs..."
	@misspell -error -source=text docs/


.PHONY: cover
cover: ## Runs go test with coverage
	@echo "==> $@"
	$(GO) test -race -coverprofile=coverage.txt -tags "$(BUILDTAGS)" $(shell $(GO) list ./... | grep -v vendor | grep -v github.com/pomerium/pomerium/integration)

.PHONY: clean
clean: ## Cleanup any build binaries or packages.
	@echo "==> $@"
	$(RM) -r $(BINDIR)
	$(RM) -r $(BUILDDIR)

.PHONY: snapshot
snapshot: ## Builds the cross-compiled binaries, naming them in such a way for release (eg. binary-GOOS-GOARCH)
	@echo "==> $@"
	@goreleaser release --rm-dist -f .github/goreleaser.yaml --snapshot

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
