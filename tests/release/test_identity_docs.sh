#!/usr/bin/env bash
# =============================================================================
# tests/release/test_identity_docs.sh — consumer docs must teach the SAME trust
# policy the release gates enforce (#99).
#
# The regression: docs shipped `--certificate-identity-regexp '<repo>/.*'`,
# which accepts a signature from ANY workflow in the repository — including
# scheduled-rebuild candidates that must never satisfy the production identity —
# while policies/cosign-identities.yaml and the release gates required an exact
# workflow file and ref class.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "wildcard gate self-test passes"      "bash scripts/assert-no-identity-wildcards.sh --self-test >/dev/null"
ck "no wildcard identity in the repo"    "bash scripts/assert-no-identity-wildcards.sh >/dev/null"
ck "gate is wired into make validate"    "grep -q 'assert-no-identity-wildcards.sh' Makefile"
ck "gate is wired into ci.yml"           "grep -q 'assert-no-identity-wildcards.sh' .github/workflows/ci.yml"

# The strict verifier must be the PRIMARY documented path, with the inputs a
# consumer needs to bind an image to a release.
ck "sbom-and-signing documents the strict verifier" \
   "grep -q 'verify-image-release-identity.sh' docs/sbom-and-signing.md"
ck "docs name EXPECTED_REVISION"         "grep -q 'EXPECTED_REVISION' docs/sbom-and-signing.md"
ck "docs name EXPECTED_ROLE=rc-publisher" \
   "grep -qE \"EXPECTED_ROLE=?'?[= ]*'?rc-publisher\" docs/sbom-and-signing.md"
ck "docs tell consumers to pin by digest" \
   "grep -q 'php-fpm@sha256:' docs/sbom-and-signing.md"

# Every raw cosign example that survives must carry an anchored identity.
ck "raw examples anchor to a workflow file and ref" \
   "! grep -rl 'certificate-identity-regexp' README.md docs/ policies/ \
      | xargs grep -L 'workflows/publish-(ghcr|rc)\\\\.yml@refs/heads/master' | grep -q ."

# The 'open hardening item' claim is retired — identities ARE pinned.
ck "release-security.md no longer calls identity pinning open" \
   "! grep -q 'Identity pinning — open hardening item' docs/release-security.md"

echo "----"; [ "$fail" -eq 0 ] && echo "test_identity_docs: PASS" || echo "test_identity_docs: FAIL"
exit $fail
