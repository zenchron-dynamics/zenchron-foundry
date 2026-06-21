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
	--label org.opencontainers.image.source="https://github.com/$(NAMESPACE)/zenchron-foundry" \
	--label org.opencontainers.image.revision="$(VCS_REF)" \
	--label org.opencontainers.image.created="$(BUILD_DATE)"

.PHONY: help doctor init hooks lint build build-php-fpm build-php-cli build-php-worker \
        build-frankenphp build-caddy build-nginx scan sbom publish clean check-structure \
        validate build-test scan-local smoke-all ci-local

help: ## Show this help
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

doctor: ## Check local tool availability with install hints (informational)
	@echo "Tool availability for local development (CI provides these regardless):"
	@printf '%s\n' \
	  "docker:Docker Engine:https://docs.docker.com/get-docker/" \
	  "docker-buildx:Buildx (docker buildx):bundled with Docker Desktop / docker-buildx pkg" \
	  "hadolint:Dockerfile lint:brew install hadolint" \
	  "shellcheck:Shell lint:brew install shellcheck" \
	  "yamllint:YAML lint:pipx install yamllint" \
	  "markdownlint:Markdown lint:npm i -g markdownlint-cli" \
	  "trivy:Vuln scan:brew install trivy" \
	  "grype:Vuln scan:brew install grype" \
	  "syft:SBOM:brew install syft" \
	  "cosign:Signing:brew install cosign" \
	  "gitleaks:Secret scan:brew install gitleaks" \
	  "semgrep:SAST:pipx install semgrep" \
	  "pre-commit:Hook framework:pipx install pre-commit" \
	  "gh:GitHub CLI (release/CI checks):brew install gh" \
	| while IFS=: read -r bin desc hint; do \
	    if [ "$$bin" = "docker-buildx" ]; then \
	      if docker buildx version >/dev/null 2>&1; then ok=1; else ok=0; fi; \
	    elif command -v "$$bin" >/dev/null 2>&1; then ok=1; else ok=0; fi; \
	    if [ "$$ok" = 1 ]; then printf "  \033[32m✓\033[0m %-14s %s\n" "$$bin" "$$desc"; \
	    else printf "  \033[31m✗\033[0m %-14s %-28s install: %s\n" "$$bin" "$$desc" "$$hint"; fi; \
	  done
	@echo "(✗ tools only affect LOCAL workflows; CI installs its own.)"

init: ## Bootstrap local dev environment (tool check + hooks)
	@bash scripts/install-hooks.sh
	@$(MAKE) --no-print-directory doctor

hooks: ## Install/refresh git pre-commit hooks
	@bash scripts/install-hooks.sh

lint: ## Run all linters (dockerfiles, shell, yaml, md, secrets)
	@bash scripts/lint-dockerfiles.sh
	@command -v pre-commit >/dev/null && pre-commit run --all-files || \
		echo "pre-commit not installed; run 'make hooks'"

check-structure: ## Verify required repository layout exists
	@bash scripts/check-structure.sh
	@bash scripts/assert-no-wolfi.sh

# --- Local CI-equivalent harness (mirrors .github/workflows/ci.yml + scan-images.yml).
#     Use during a GitHub Actions freeze; GitHub CI remains MANDATORY before merge.
validate: ## CI-equivalent static checks: structure, supply-chain guard, lint, compose (graceful)
	@bash scripts/validate-local.sh

build-test: ## Build representative images locally (PHP 8.3 + 8.4 + nginx + caddy)
	@$(MAKE) --no-print-directory build PHP=8.3
	@$(MAKE) --no-print-directory build PHP=8.4
	@echo "==> build-test OK (php 8.3/8.4 fpm/cli/worker/frankenphp + nginx + caddy)"

scan-local: ## Trivy gate + Grype/Syft (advisory) on local images; reports missing tools
	@bash scripts/scan-local.sh $(PHP)

smoke-all: ## Runtime smoke (non-root, read-only, heartbeat, SIGTERM, FastCGI, HTTP/readiness)
	@bash scripts/smoke-local.sh $(PHP)

ci-local: ## Full local CI-equivalent: validate -> build-test -> scan-local -> smoke-all
	@$(MAKE) --no-print-directory validate
	@$(MAKE) --no-print-directory build-test
	@$(MAKE) --no-print-directory scan-local PHP=8.4
	@$(MAKE) --no-print-directory smoke-all  PHP=8.4
	@echo "==> ci-local complete. NOTE: GitHub CI is still REQUIRED before any merge."

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
	@test -d images/php-worker/$(PHP) || { echo "ERROR: php-worker has no version '$(PHP)' (valid: 8.3 8.4)"; exit 1; }
	$(BUILDX) --platform $(PLATFORMS) $(LABEL_ARGS) \
		--label org.opencontainers.image.version="$(PHP)-$(TAG_SUFFIX)" \
		-t $(WORKER_IMAGE):$(PHP)-$(TAG_SUFFIX) --load images/php-worker/$(PHP)

build-frankenphp: ## Build php-frankenphp:$(PHP)-$(TAG_SUFFIX) (8.3/8.4 only)
	@test -d images/php-frankenphp/$(PHP) || { echo "ERROR: php-frankenphp supports only 8.3/8.4 (got PHP=$(PHP)). FrankenPHP requires PHP >= 8.2."; exit 1; }
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
