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
        validate build-test smoke-all scan-local sbom-local verify-local ci-local

# STRICT=1 turns every local gate into a hard requirement (no SKIPPED). Without
# it, missing tools are reported as SKIPPED so the harness still runs offline.
# Scripts honor LOCAL=1 (lenient skip); STRICT clears it so they fail hard.
LOCAL_FLAG := $(if $(STRICT),,LOCAL=1)

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
	  "docker-compose:Compose v2:bundled with Docker Desktop / docker-compose-plugin" \
	  "act:Local Actions runner:brew install act" \
	  "gh:GitHub CLI (release/CI checks):brew install gh" \
	| while IFS=: read -r bin desc hint; do \
	    if [ "$$bin" = "docker-buildx" ]; then \
	      if docker buildx version >/dev/null 2>&1; then ok=1; else ok=0; fi; \
	    elif [ "$$bin" = "docker-compose" ]; then \
	      if docker compose version >/dev/null 2>&1; then ok=1; else ok=0; fi; \
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
	@if command -v pre-commit >/dev/null 2>&1; then \
		pre-commit run --all-files; \
	else \
		echo "pre-commit not installed; run 'make hooks'"; \
	fi

check-structure: ## Verify required repository layout exists
	@bash scripts/check-structure.sh
	@bash scripts/assert-no-wolfi.sh

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

publish: ## Publishing is CI-only. There is no local production push path.
	@echo "Publishing is done ONLY by CI, and production tags ONLY by the protected"
	@echo "promotion workflow:"
	@echo "  RC candidates : .github/workflows/publish-rc.yml"
	@echo "  stable *-prod : .github/workflows/promote-stable.yml (exact-digest retag)"
	@echo "The local publish-all.sh bypass was removed (it pushed *-prod with || true)."
	@exit 1

clean: ## Remove local build/scan artifacts (no image deletion)
	rm -rf dist artifacts ./*.sbom.json ./*.trivy.json ./*.grype.json ./*.sarif checksums.txt
	@echo "cleaned local artifacts (images left intact)"

# --- Local CI harness (mirrors the hosted gates) ----------------------------

validate: ## Static gates: structure, supply-chain guard, action/container/runner-trust pinning, matrix
	@bash scripts/check-structure.sh
	@bash scripts/assert-no-wolfi.sh
	@bash scripts/assert-pinned-actions.sh
	@bash scripts/assert-pr-workflows-github-hosted.sh
	@bash scripts/assert-dependabot-manifests.sh
	@bash scripts/assert-no-identity-wildcards.sh
	@bash scripts/assert-pinned-containers.sh
	@bash scripts/assert-image-matrix.sh
	@$(LOCAL_FLAG) bash scripts/verify-base-images.sh

build-test: ## Build all 10 images locally (load), no push
	@$(MAKE) --no-print-directory build-php-cli build-php-fpm build-php-worker build-frankenphp PHP=8.3
	@$(MAKE) --no-print-directory build-php-cli build-php-fpm build-php-worker build-frankenphp PHP=8.4
	@$(MAKE) --no-print-directory build-caddy build-nginx

smoke-all: ## Runtime smoke tests for all 10 images (fails if zero tested)
	@bash scripts/smoke-all.sh

.PHONY: runtime-contract
runtime-contract: ## Hardened runtime contract across the whole matrix (#110)
	@bash scripts/runtime-contract.sh --all --json runtime-contract-evidence.json

.PHONY: reproducibility
reproducibility: ## Two --no-cache builds per representative family, compared (#101)
	@bash scripts/reproducibility-check.sh images/nginx nginx
	@bash scripts/reproducibility-check.sh images/caddy caddy
	@bash scripts/reproducibility-check.sh images/php-cli/8.4 php-cli-8.4
	@bash scripts/reproducibility-check.sh images/php-frankenphp/8.4 php-frankenphp-8.4

.PHONY: supply-chain
supply-chain: ## Inventory integrity + upstream drift for every embedded input (#123)
	@bash scripts/assert-supply-chain-inputs.sh --check-upstream

scan-local: ## Trivy/Grype scan locally (SKIPPED if tools absent unless STRICT=1)
	@if command -v trivy >/dev/null && command -v grype >/dev/null; then \
	  bash scripts/scan-all.sh; \
	elif [ -n "$(STRICT)" ]; then \
	  echo "STRICT: trivy/grype required but missing"; exit 1; \
	else echo "SKIPPED: trivy/grype not installed (set STRICT=1 to require)"; fi

sbom-local: ## Generate SBOM for the current php-fpm image (SKIPPED if syft absent)
	@if command -v syft >/dev/null; then \
	  IMAGE=$(FPM_IMAGE):$(PHP)-$(TAG_SUFFIX) bash scripts/generate-sbom.sh; \
	elif [ -n "$(STRICT)" ]; then \
	  echo "STRICT: syft required but missing"; exit 1; \
	else echo "SKIPPED: syft not installed (set STRICT=1 to require)"; fi

verify-local: ## Verify release artifacts + base images (LOCAL skips missing tools)
	@$(LOCAL_FLAG) bash scripts/verify-base-images.sh
	@$(LOCAL_FLAG) bash scripts/verify-release-artifacts.sh

verify-governance: ## Verify live GitHub governance == policies/repository-governance.yaml (needs gh + network)
	@$(LOCAL_FLAG) bash scripts/verify-repo-governance.sh $(if $(EVIDENCE),--evidence $(EVIDENCE),)

ci-local: ## Full local CI: validate + build-test + smoke-all (+scan/sbom). STRICT=1 = all gates required.
	@$(MAKE) --no-print-directory validate
	@$(MAKE) --no-print-directory build-test
	@$(MAKE) --no-print-directory smoke-all
	@$(MAKE) --no-print-directory scan-local
	@$(MAKE) --no-print-directory sbom-local
	@echo "==> ci-local complete (STRICT=$(if $(STRICT),1,0))"
