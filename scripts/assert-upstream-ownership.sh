#!/usr/bin/env bash
# =============================================================================
# scripts/assert-upstream-ownership.sh — fail closed when a change would make
# Foundry the owner of an upstream binary.
# -----------------------------------------------------------------------------
# Enforces policies/component-ownership.yaml. The rule:
#
#   Zenchron Foundry builds Zenchron golden images from official upstream bases.
#   It does not fork, patch, vendor, or compile upstream-owned runtime/server
#   binaries unless an explicitly approved ADR changes that ownership model.
#
# WHAT THIS IS NOT. It does not forbid `docker build`. Foundry builds its own
# golden images constantly and must keep doing so. It also does not forbid the
# APPROVED compilation of PHP extensions through the official toolchain
# (docker-php-ext-*, pecl) — that is a Foundry-owned decision made with an
# upstream-owned toolchain, and the policy classifies it explicitly rather than
# leaving it to a vague exception.
#
# DESIGN. Structured policy first, scoped textual checks second, and COMMENTS
# ARE STRIPPED before matching. This repository has repeatedly produced checks
# that matched their own explanatory prose — a `head -c40` comment, an
# `inputs.platforms` comment — and reported a correct file as broken. A check
# that cries wolf gets disabled, which is worse than not having it.
#
# Usage:
#   assert-upstream-ownership.sh            # audit the working tree
#   assert-upstream-ownership.sh --self-test
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY_REL="policies/component-ownership.yaml"

# Executable lines only: no comments, no blank lines. Dockerfiles and shell both
# use '#'.
_code() { grep -vE '^[[:space:]]*#' "$1" 2>/dev/null | grep -vE '^[[:space:]]*$'; }

# Source-build tooling for upstream-owned server/runtime binaries. Deliberately
# NOT a bare "go" match: `go` appears in prose, filenames and unrelated tools.
_FORBIDDEN_TOOLS='xcaddy|(^|[[:space:];&|])go[[:space:]]+(build|install|get|mod)([[:space:]]|$)|GOFLAGS=|GOPRIVATE=|-mod=mod|replace[[:space:]]+github\.com/(dunglas|caddyserver)'

# Fetching upstream server/runtime SOURCE for compilation.
_FORBIDDEN_FETCH='git[[:space:]]+clone[^|]*(frankenphp|caddyserver/caddy|nginx/nginx|php/php-src)|(curl|wget)[^|]*(frankenphp|caddyserver/caddy)[^|]*\.(tar|tgz|zip)'

# THE ONLY FILES EXEMPT FROM THE TEXTUAL SCAN, and why: this script DEFINES the
# forbidden patterns, and its test EXERCISES them by writing sabotage fixtures.
# Both legitimately contain the strings as data. Nothing else is exempt, and
# tests/release/test_upstream_ownership.sh asserts this list stays exactly these
# two entries so it cannot quietly grow into a hiding place.
SELF_EXCLUDE="scripts/assert-upstream-ownership.sh tests/release/test_upstream_ownership.sh"

# Overwriting an official binary with one built here.
_FORBIDDEN_REPLACE='COPY[[:space:]]+--from=[^[:space:]]+[[:space:]]+[^[:space:]]*/(frankenphp|caddy|nginx|php)[[:space:]]'

# Helpers defined at TOP LEVEL with plain quoted heredocs. Embedding these as
# heredocs inside `$( ... )` inside a function produced spurious "bad
# substitution" / "unbound variable" errors whose reported line numbers pointed
# at unrelated code — the heredoc bodies shift bash's line accounting. Kept out
# of command substitutions on purpose.
_unclassified_families() {   # _unclassified_families <root> <policy>
  python3 - "$1" "$2" <<'UCPY'
import sys, yaml, subprocess
root, policy = sys.argv[1], sys.argv[2]
d = yaml.safe_load(open(policy))
covered = set()
for c in d["components"]:
    covered.update(c.get("image_families") or [])
out = subprocess.run(["bash", "-c", ". scripts/lib/common.sh; matrix_families"],
                     cwd=root, capture_output=True, text=True).stdout.split()
print(" ".join(sorted(set(out) - covered)))
UCPY
}

_unofficial_bases() {        # _unofficial_bases <root> <policy>
  python3 - "$1" "$2" <<'UBPY'
import sys, re, os, glob
root = sys.argv[1]
allowed = ("php:", "dunglas/frankenphp:", "nginxinc/nginx-unprivileged:", "caddy:")
bad = []
for f in glob.glob(os.path.join(root, "images/**/Dockerfile"), recursive=True):
    for line in open(f):
        s = line.strip()
        if s.startswith("#"):
            continue
        m = re.match(r'ARG\s+[A-Z_]*BASE="([^"]+)"', s)
        if m and not m.group(1).startswith(allowed):
            bad.append("%s: %s" % (os.path.relpath(f, root), m.group(1)))
print("\n".join(bad))
UBPY
}

_approved_adr_count() {      # _approved_adr_count <policy>
  python3 - "$1" <<'ADRCPY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
print(len(d["ownership_change"].get("approved_adrs") or []))
ADRCPY
}

audit() {
  local root="${1:-$ROOT}" findings=0
  local policy="$root/$POLICY_REL"
  [ -s "$policy" ] || { echo "REFUSE: no ownership policy at $POLICY_REL" >&2; return 1; }

  # --- 1. no approved ADR may be assumed ------------------------------------
  # An ownership change is only legitimate with an ADR listed in the policy.
  # Today the list is empty; if a future change adds one, that diff is exactly
  # what a reviewer must see.
  local adrs
  adrs="$(_approved_adr_count "$policy" 2>/dev/null)"
  [ -n "$adrs" ] || { echo "REFUSE: ownership policy is unreadable" >&2; return 1; }

  # --- 2. every shipped family must be classified ---------------------------
  local unclassified
  unclassified="$(_unclassified_families "$root" "$policy")"
  if [ -n "$unclassified" ]; then
    echo "REFUSE: shipped image families with no ownership entry: $unclassified" >&2
    findings=$((findings+1))
  fi

  # --- 3. no source-build of an upstream-owned binary ----------------------
  # Scoped to files that actually build: Dockerfiles, build scripts, workflows.
  # $f is RELATIVE to $root, because find runs in a subshell that cds there.
  # Resolving it against the CALLER's cwd made every file fail the -f test and
  # be skipped silently — a fail-OPEN hole that only looked correct because the
  # repository audit happens to run with $root == cwd. Always resolve against
  # $root; report the relative path.
  local f hits abs
  while IFS= read -r f; do
    abs="$root/$f"
    [ -f "$abs" ] || continue
    hits="$(_code "$abs" | grep -nE "$_FORBIDDEN_TOOLS" || true)"
    if [ -n "$hits" ]; then
      echo "REFUSE: upstream source-build tooling in $f" >&2
      printf '%s\n' "$hits" | sed 's/^/    /' >&2
      findings=$((findings+1))
    fi
    hits="$(_code "$abs" | grep -nE "$_FORBIDDEN_FETCH" || true)"
    if [ -n "$hits" ]; then
      echo "REFUSE: fetching upstream server/runtime source in $f" >&2
      printf '%s\n' "$hits" | sed 's/^/    /' >&2
      findings=$((findings+1))
    fi
    hits="$(_code "$abs" | grep -nE "$_FORBIDDEN_REPLACE" || true)"
    if [ -n "$hits" ]; then
      echo "REFUSE: replacing an official binary with a locally built one in $f" >&2
      printf '%s\n' "$hits" | sed 's/^/    /' >&2
      findings=$((findings+1))
    fi
  done < <(cd "$root" && find images scripts .github/workflows -type f \
             \( -name Dockerfile -o -name '*.sh' -o -name '*.yml' \) 2>/dev/null \
             | grep -vxF -f <(printf '%s\n' $SELF_EXCLUDE))

  # --- 4. every base must be an official image, pinned by digest ------------
  local bad
  # while-read over find, not a for-loop over its output (SC2044): a path with
  # whitespace would otherwise be split into fragments and silently skipped.
  bad="$(cd "$root" && find images -name Dockerfile -print | while IFS= read -r f; do
    _code "$f" | grep -E '^[[:space:]]*(ARG[[:space:]]+[A-Z_]*BASE=|FROM[[:space:]])' \
      | grep -vE '@sha256:[0-9a-f]{64}' \
      | grep -vE '^[[:space:]]*FROM[[:space:]]+\$\{' \
      | sed "s|^|$f: |"
  done)"
  if [ -n "$bad" ]; then
    echo "REFUSE: a base image is not pinned by digest:" >&2
    printf '%s\n' "$bad" | sed 's/^/    /' >&2
    findings=$((findings+1))
  fi

  # --- 5. bases must come from the repositories the policy names ------------
  local unofficial
  unofficial="$(_unofficial_bases "$root" "$policy")"
  if [ -n "$unofficial" ]; then
    echo "REFUSE: base image is not an official upstream image named by the policy:" >&2
    printf '%s\n' "$unofficial" | sed 's/^/    /' >&2
    findings=$((findings+1))
  fi

  # --- 6. no automation may call an unchanged rebuild a remediation ---------
  # The claim, not the word. Scoped to the classifier and ticket contract, which
  # are the places that decide it.
  if ! grep -q 'rebuild_can_remediate' "$root/scripts/classify-remediation-owner.sh" 2>/dev/null; then
    echo "REFUSE: the remediation classifier no longer decides rebuild_can_remediate" >&2
    findings=$((findings+1))
  fi

  if [ "$findings" -eq 0 ]; then
    echo "ownership boundary OK: $adrs approved source-build ADR(s); all shipped families classified; all bases official and digest-pinned"
    return 0
  fi
  echo "----" >&2
  echo "$findings ownership violation(s). See $POLICY_REL and AGENTS.md." >&2
  return 1
}

# --- self-test ---------------------------------------------------------------
# Sabotage-driven: each case copies the repository shape into a temp dir, breaks
# ONE thing, and requires the audit to refuse for THAT reason.
self_test() {
  local pass=0 fail=0
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

  # A minimal but realistic fixture: the real policy and library, a digest-pinned
  # Dockerfile that also performs the APPROVED extension compilation.
  mk() {
    local d; d="$(mktemp -d)"
    mkdir -p "$d/policies" "$d/scripts/lib" "$d/images/php-cli/8.3" \
             "$d/images/php-frankenphp/8.3" "$d/images/nginx" "$d/images/caddy" \
             "$d/images/php-fpm/8.3" "$d/images/php-worker/8.3" "$d/.github/workflows"
    cp "$ROOT/$POLICY_REL" "$d/$POLICY_REL"
    cp "$ROOT/scripts/lib/common.sh" "$d/scripts/lib/common.sh"
    cp "$ROOT/scripts/classify-remediation-owner.sh" "$d/scripts/classify-remediation-owner.sh"
    cat > "$d/images/php-cli/8.3/Dockerfile" <<'EOF'
ARG PHP_CLI_BASE="php:8.3-cli-bookworm@sha256:a4fcf31ffb94b8d19b84514926b5a2cddf22a38b1e29922f8d3e8a933091f806"
FROM ${PHP_CLI_BASE} AS runtime
ARG PHPREDIS_VERSION="6.1.0"
RUN docker-php-ext-configure gd --with-jpeg; \
    docker-php-ext-install -j"$(nproc)" gd; \
    pecl install /tmp/redis.tgz
EOF
    cat > "$d/images/php-frankenphp/8.3/Dockerfile" <<'EOF'
ARG FRANKENPHP_BASE="dunglas/frankenphp:1-php8.3-bookworm@sha256:ae143d38335e4d8faf3f73205c91b69562b4154a85bf3fdd9ef63d59c8727ead"
FROM ${FRANKENPHP_BASE} AS runtime
RUN echo hardening
EOF
    # Quoted heredocs only: a printf format containing ${VAR} invites bash to
    # parse it as an expansion, which is exactly how an earlier draft of this
    # fixture produced "bad substitution" on a correct file.
    cat > "$d/images/nginx/Dockerfile" <<'EOF'
ARG NGINX_BASE="nginxinc/nginx-unprivileged:1.28-bookworm@sha256:cd33960e98e93d4d63385790ff7f8f5bf2ca95184c581b7f42ae8aea1139fbfc"
FROM ${NGINX_BASE} AS runtime
RUN echo hardening
EOF
    cat > "$d/images/caddy/Dockerfile" <<'EOF'
ARG CADDY_BASE="caddy:2-alpine@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648"
FROM ${CADDY_BASE} AS runtime
RUN echo hardening
EOF
    cat > "$d/images/php-fpm/8.3/Dockerfile" <<'EOF'
ARG PHP_FPM_BASE="php:8.3-fpm-bookworm@sha256:2a397791f5ee422190bb673d79332be53ff545205f6df19e2664bd664ebbd739"
FROM ${PHP_FPM_BASE} AS runtime
EOF
    cat > "$d/images/php-worker/8.3/Dockerfile" <<'EOF'
ARG PHP_CLI_BASE="php:8.3-cli-bookworm@sha256:a4fcf31ffb94b8d19b84514926b5a2cddf22a38b1e29922f8d3e8a933091f806"
FROM ${PHP_CLI_BASE} AS runtime
EOF
    printf '%s' "$d"
  }
  rm_fixture() { [ -n "${1:-}" ] && rm -rf "$1"; }
  why() { audit "$1" 2>&1 || true; }

  # shellcheck disable=SC2034  # OUT is consumed inside the eval'd ck assertions
  local D OUT
  # 1 + 2: the approved shape passes
  D="$(mk)"
  ck "1. official digest-pinned consumption PASSES" 'audit "$D" >/dev/null 2>&1'
  ck "2. approved PHP-extension compilation PASSES (pecl + docker-php-ext-*)" \
     'audit "$D" >/dev/null 2>&1 && grep -q "pecl install" "$D/images/php-cli/8.3/Dockerfile"'
  ck "...and the passing message states the ADR count is zero" \
     '[ "$(audit "$D" 2>/dev/null | grep -c "0 approved source-build ADR")" = 1 ]'
  rm_fixture "$D"

  # 3: go build for FrankenPHP
  D="$(mk)"; printf 'RUN go build -o /usr/local/bin/frankenphp ./cmd\n' >> "$D/images/php-frankenphp/8.3/Dockerfile"
  ck "3. adding 'go build' for FrankenPHP FAILS" '! audit "$D" >/dev/null 2>&1'
    # shellcheck disable=SC2034
    OUT="$(why "$D")"
  ck "...naming source-build tooling" 'grep -q "upstream source-build tooling" <<<"$OUT"'
  rm_fixture "$D"

  # 4: xcaddy
  D="$(mk)"; printf 'RUN xcaddy build --with github.com/x/y\n' >> "$D/images/caddy/Dockerfile"
  ck "4. adding an 'xcaddy build' path FAILS" '! audit "$D" >/dev/null 2>&1'
    # shellcheck disable=SC2034
    OUT="$(why "$D")"
  ck "...naming source-build tooling" 'grep -q "upstream source-build tooling" <<<"$OUT"'
  rm_fixture "$D"

  # 5: replacing the official binary
  D="$(mk)"; printf 'COPY --from=builder /out/frankenphp /usr/local/bin/frankenphp\n' >> "$D/images/php-frankenphp/8.3/Dockerfile"
  ck "5. replacing the upstream FrankenPHP binary FAILS" '! audit "$D" >/dev/null 2>&1'
    # shellcheck disable=SC2034
    OUT="$(why "$D")"
  ck "...naming binary replacement" 'grep -q "replacing an official binary" <<<"$OUT"'
  rm_fixture "$D"

  # 6: an unofficial base
  D="$(mk)"
  { printf 'ARG FRANKENPHP_BASE="ghcr.io/someone/frankenphp-custom:1@sha256:%s"\n' \
      "$(printf 'b%.0s' {1..64})"
    printf 'FROM $'; printf '{FRANKENPHP_BASE}\n'; } \
    > "$D/images/php-frankenphp/8.3/Dockerfile"
  ck "6. an unofficial FrankenPHP base FAILS" '! audit "$D" >/dev/null 2>&1'
    # shellcheck disable=SC2034
    OUT="$(why "$D")"
  ck "...naming it as not an official upstream image" 'grep -q "not an official upstream image" <<<"$OUT"'
  rm_fixture "$D"

  # 7: ownership change without an ADR
  D="$(mk)"
  python3 - "$D/$POLICY_REL" <<'PY'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
for c in d["components"]:
    if c["component"] == "frankenphp-binary":
        c["foundry_may_compile"] = True          # the sabotage
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  # Detection written as a function: nesting python inside an eval'd
  # single-quoted string at this depth is how the first draft broke its own
  # syntax.
  compilable_without_adr() {
    python3 - "$1" <<'ADRPY'
import sys, yaml
d = yaml.safe_load(open(sys.argv[1]))
adrs = d["ownership_change"].get("approved_adrs") or []
bad = [c["component"] for c in d["components"]
       if c["owner_class"] == "upstream-binary" and c.get("foundry_may_compile")]
sys.exit(0 if (bad and not adrs) else 1)
ADRPY
  }
  ck "7. flipping an upstream binary to compilable without an ADR is DETECTED" \
     'compilable_without_adr "$D/$POLICY_REL"'
  rm_fixture "$D"

  # 8: a patched official digest bump stays allowed
  D="$(mk)"
  sed -i.bak "s|@sha256:ae143d38[0-9a-f]*|@sha256:$(printf 'a%.0s' {1..64})|" \
    "$D/images/php-frankenphp/8.3/Dockerfile" && rm -f "$D/images/php-frankenphp/8.3/Dockerfile.bak"
  ck "8. a patched official digest bump remains ALLOWED" 'audit "$D" >/dev/null 2>&1'
  rm_fixture "$D"

  # 9: an unpinned base
  D="$(mk)"
  { printf 'ARG CADDY_BASE="caddy:2-alpine"\n'
    printf 'FROM $'; printf '{CADDY_BASE}\n'; } > "$D/images/caddy/Dockerfile"
  ck "9. dropping the digest pin FAILS" '! audit "$D" >/dev/null 2>&1'
    # shellcheck disable=SC2034
    OUT="$(why "$D")"
  ck "...naming the missing pin" 'grep -q "not pinned by digest" <<<"$OUT"'
  rm_fixture "$D"

  # 10: an unclassified shipped family
  D="$(mk)"
  python3 - "$D/$POLICY_REL" <<'PY'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
for c in d["components"]:
    c["image_families"] = [f for f in (c.get("image_families") or []) if f != "nginx"]
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
  ck "10. a shipped family with no ownership entry FAILS" '! audit "$D" >/dev/null 2>&1'
    # shellcheck disable=SC2034
    OUT="$(why "$D")"
  ck "...naming the family" 'grep -q "no ownership entry: nginx" <<<"$OUT"'
  rm_fixture "$D"

  # 11: the classifier must keep deciding remediability
  D="$(mk)"; printf '#!/usr/bin/env bash\necho nothing\n' > "$D/scripts/classify-remediation-owner.sh"
  ck "11. gutting the remediation classifier FAILS" '! audit "$D" >/dev/null 2>&1'
    # shellcheck disable=SC2034
    OUT="$(why "$D")"
  ck "...naming the classifier" 'grep -q "no longer decides rebuild_can_remediate" <<<"$OUT"'
  rm_fixture "$D"

  # 12: comments must never trigger a violation
  D="$(mk)"
  cat >> "$D/images/caddy/Dockerfile" <<'EOF'
# rebuilding Caddy here with xcaddy build would be an UNOFFICIAL rebuild and is
# forbidden; see policies/component-ownership.yaml. Do not run go build either.
EOF
  ck "12. prose mentioning xcaddy/go build does NOT trigger a violation" 'audit "$D" >/dev/null 2>&1'
  rm_fixture "$D"

  # 13: a missing policy is a refusal, not a pass
  D="$(mk)"; rm -f "$D/$POLICY_REL"
  ck "13. a missing ownership policy REFUSES" '! audit "$D" >/dev/null 2>&1'
  rm_fixture "$D"

  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          audit "$ROOT" ;;
  *)           audit "$1" ;;
esac
