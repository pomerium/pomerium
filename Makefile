# Setup name variables for the package/tool
PREFIX?=$(shell pwd)

NAME := pomerium
PKG := github.com/pomerium/$(NAME)

BUILDDIR := ${PREFIX}/dist
BINDIR := ${PREFIX}/bin
GO111MODULE=on
CGO_ENABLED := 0
# Set any default go build tags
BUILDTAGS :=

# Populate version variables
# Add to compile time flags
VERSION := $(shell cat VERSION)
GITCOMMIT := $(shell git rev-parse --short HEAD)
GITUNTRACKEDCHANGES := $(shell git status --porcelain --untracked-files=no)
BUILDMETA:=
ifneq ($(GITUNTRACKEDCHANGES),"")
	BUILDMETA := dirty
endif
CTIMEVAR=-X $(PKG)/internal/version.GitCommit=$(GITCOMMIT) \
	-X $(PKG)/internal/version.Version=$(VERSION) \
	-X $(PKG)/internal/version.BuildMeta=$(BUILDMETA) \
	-X $(PKG)/internal/version.ProjectName=$(NAME) \
	-X $(PKG)/internal/version.ProjectURL=$(PKG)
GO_LDFLAGS=-ldflags "-s -w $(CTIMEVAR)"
GOOSARCHES = linux/amd64 darwin/amd64 windows/amd64


.PHONY: all
all: clean build lint spellcheck test ## Runs a clean, build, fmt, lint, test, and vet.

.PHONY: tag
tag: ## Create a new git tag to prepare to build a release
	git tag -sa $(VERSION) -m "$(VERSION)"
	@echo "Run git push origin $(VERSION) to push your new tag to GitHub."

.PHONY: build
build: ## Builds dynamic executables and/or packages.
	@echo "==> $@"
	@CGO_ENABLED=0 GO111MODULE=on go build -tags "$(BUILDTAGS)" ${GO_LDFLAGS} -o $(BINDIR)/$(NAME) ./cmd/"$(NAME)"

.PHONY: lint
lint: ## Verifies `golint` passes.
	@echo "==> $@"
	@GO111MODULE=off go get -u github.com/golangci/golangci-lint/cmd/golangci-lint
	@golangci-lint run ./...

.PHONY: test
test: ## Runs the go tests.
	@echo "==> $@"
	@go test -tags "$(BUILDTAGS)" $(shell go list ./... | grep -v vendor)

.PHONY: spellcheck
spellcheck: # Spellcheck docs
	@echo "==> Spell checking docs..."
	@GO111MODULE=off go get -u github.com/client9/misspell/cmd/misspell
	@misspell -error -source=text docs/


.PHONY: cover
cover: ## Runs go test with coverage
	@echo "" > coverage.txt
	@for d in $(shell go list ./... | grep -v vendor); do \
		go test -race -coverprofile=profile.out -covermode=atomic "$$d"; \
		if [ -f profile.out ]; then \
			cat profile.out >> coverage.txt; \
			rm profile.out; \
		fi; \
	done;

.PHONY: clean
clean: ## Cleanup any build binaries or packages.
	@echo "==> $@"
	$(RM) -r $(BINDIR)
	$(RM) -r $(BUILDDIR)

define buildpretty
mkdir -p $(BUILDDIR)/$(1)/$(2);
GOOS=$(1) GOARCH=$(2) CGO_ENABLED=0 GO111MODULE=on go build \
	 -o $(BUILDDIR)/$(1)/$(2)/$(NAME) \
	 ${GO_LDFLAGS_STATIC} ./cmd/$(NAME);
md5sum $(BUILDDIR)/$(1)/$(2)/$(NAME) > $(BUILDDIR)/$(1)/$(2)/$(NAME).md5;
sha256sum $(BUILDDIR)/$(1)/$(2)/$(NAME) > $(BUILDDIR)/$(1)/$(2)/$(NAME).sha256;
endef

.PHONY: cross
cross: ## Builds the cross-compiled binaries, creating a clean directory structure (eg. GOOS/GOARCH/binary)
	@echo "+ $@"
	$(foreach GOOSARCH,$(GOOSARCHES), $(call buildpretty,$(subst /,,$(dir $(GOOSARCH))),$(notdir $(GOOSARCH))))

define buildrelease
GOOS=$(1) GOARCH=$(2) CGO_ENABLED=0 GO111MODULE=on go build ${GO_LDFLAGS} \
	 -o $(BUILDDIR)/$(NAME)-$(1)-$(2) \
	 ${GO_LDFLAGS_STATIC} ./cmd/$(NAME);
md5sum $(BUILDDIR)/$(NAME)-$(1)-$(2) > $(BUILDDIR)/$(NAME)-$(1)-$(2).md5;
sha256sum $(BUILDDIR)/$(NAME)-$(1)-$(2) > $(BUILDDIR)/$(NAME)-$(1)-$(2).sha256;
endef

.PHONY: release
release: ## Builds the cross-compiled binaries, naming them in such a way for release (eg. binary-GOOS-GOARCH)
	@echo "+ $@"
	$(foreach GOOSARCH,$(GOOSARCHES), $(call buildrelease,$(subst /,,$(dir $(GOOSARCH))),$(notdir $(GOOSARCH))))

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
