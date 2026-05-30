# docker-platform — developer entrypoint.
# Safe by default: no hidden destructive actions, no implicit push.
# Override variables on the command line, e.g.  make build-php-fpm PHP=8.4

SHELL := /usr/bin/env bash
.DEFAULT_GOAL := help

# --- Configuration ----------------------------------------------------------
REGISTRY        ?= ghcr.io
NAMESPACE       ?= zenchron-dynamics
PHP             ?= 8.3
PLATFORMS       ?= linux/amd64
TAG_SUFFIX      ?= prod
# Populate from git/CI; used for reproducible OCI labels.
VCS_REF         ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE      ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
DATE_TAG        ?= $(shell date -u +%Y.%m.%d)

FPM_IMAGE       := $(REGISTRY)/$(NAMESPACE)/php-fpm
CLI_IMAGE       := $(REGISTRY)/$(NAMESPACE)/php-cli
WORKER_IMAGE    := $(REGISTRY)/$(NAMESPACE)/php-worker
FRANKEN_IMAGE   := $(REGISTRY)/$(NAMESPACE)/php-frankenphp
CADDY_IMAGE     := $(REGISTRY)/$(NAMESPACE)/caddy
NGINX_IMAGE     := $(REGISTRY)/$(NAMESPACE)/nginx

BUILDX          := docker buildx build
LABEL_ARGS      := \
	--label org.opencontainers.image.vendor="Zenchron Dynamics" \
	--label org.opencontainers.image.source="https://github.com/$(NAMESPACE)/docker-platform" \
	--label org.opencontainers.image.revision="$(VCS_REF)" \
	--label org.opencontainers.image.created="$(BUILD_DATE)"

.PHONY: help init hooks lint build build-php-fpm build-php-cli build-php-worker \
        build-frankenphp build-caddy build-nginx scan sbom publish clean check-structure

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

init: ## Bootstrap local dev environment (tool check + hooks)
	@bash scripts/install-hooks.sh
	@echo "Verify tools: docker buildx, hadolint, trivy, grype, syft, cosign, gitleaks, shellcheck"

hooks: ## Install/refresh git pre-commit hooks
	@bash scripts/install-hooks.sh

lint: ## Run all linters (dockerfiles, shell, yaml, md, secrets)
	@bash scripts/lint-dockerfiles.sh
	@command -v pre-commit >/dev/null && pre-commit run --all-files || \
		echo "pre-commit not installed; run 'make hooks'"

check-structure: ## Verify required repository layout exists
	@bash scripts/check-structure.sh

build: build-php-fpm build-php-cli build-php-worker build-frankenphp build-caddy build-nginx ## Build everything (current PHP=)

build-php-fpm: ## Build php-fpm:$(PHP)-$(TAG_SUFFIX)
	$(BUILDX) --platform $(PLATFORMS) $(LABEL_ARGS) \
		--label org.opencontainers.image.version="$(PHP)-$(TAG_SUFFIX)" \
		-t $(FPM_IMAGE):$(PHP)-$(TAG_SUFFIX) \
		-t $(FPM_IMAGE):$(PHP)-$(TAG_SUFFIX)-$(DATE_TAG) \
		--load images/php-fpm/$(PHP)

build-php-cli: ## Build php-cli:$(PHP)-$(TAG_SUFFIX)
	$(BUILDX) --platform $(PLATFORMS) $(LABEL_ARGS) \
		--label org.opencontainers.image.version="$(PHP)-$(TAG_SUFFIX)" \
		-t $(CLI_IMAGE):$(PHP)-$(TAG_SUFFIX) --load images/php-cli/$(PHP)

build-php-worker: ## Build php-worker:$(PHP)-$(TAG_SUFFIX)
	$(BUILDX) --platform $(PLATFORMS) $(LABEL_ARGS) \
		--label org.opencontainers.image.version="$(PHP)-$(TAG_SUFFIX)" \
		-t $(WORKER_IMAGE):$(PHP)-$(TAG_SUFFIX) --load images/php-worker/$(PHP)

build-frankenphp: ## Build php-frankenphp:$(PHP)-$(TAG_SUFFIX) (8.3/8.4 only)
	$(BUILDX) --platform $(PLATFORMS) $(LABEL_ARGS) \
		--label org.opencontainers.image.version="$(PHP)-$(TAG_SUFFIX)" \
		-t $(FRANKEN_IMAGE):$(PHP)-$(TAG_SUFFIX) --load images/php-frankenphp/$(PHP)

build-caddy: ## Build caddy:$(TAG_SUFFIX)
	$(BUILDX) --platform $(PLATFORMS) $(LABEL_ARGS) \
		-t $(CADDY_IMAGE):$(TAG_SUFFIX) --load images/caddy

build-nginx: ## Build nginx:$(TAG_SUFFIX)
	$(BUILDX) --platform $(PLATFORMS) $(LABEL_ARGS) \
		-t $(NGINX_IMAGE):$(TAG_SUFFIX) --load images/nginx

scan: ## Trivy + Grype scan of current PHP php-fpm image
	@IMAGE=$(FPM_IMAGE):$(PHP)-$(TAG_SUFFIX) bash scripts/scan-all.sh

sbom: ## Generate SBOMs (syft) for current PHP php-fpm image
	@IMAGE=$(FPM_IMAGE):$(PHP)-$(TAG_SUFFIX) bash scripts/generate-sbom.sh

publish: ## Push images to GHCR (requires login; prefer CI). Guarded.
	@echo "Publishing is normally done by CI (publish-ghcr.yml)."
	@echo "To push manually you must be logged in to $(REGISTRY)."
	@read -p "Push $(NAMESPACE)/* now? [y/N] " ok; [ "$$ok" = "y" ] && bash scripts/publish-all.sh || echo "aborted"

clean: ## Remove local build/scan artifacts (no image deletion)
	rm -rf dist artifacts ./*.sbom.json ./*.trivy.json ./*.grype.json ./*.sarif checksums.txt
	@echo "cleaned local artifacts (images left intact)"
