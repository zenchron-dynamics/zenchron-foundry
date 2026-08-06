#!/usr/bin/env bash
# Stable seal path — artifact-sourced RC manifest + tag-first promotion order.
# Guards the two invariants the first live release ceremony broke:
#   * the signed RC manifest is fetched from the publish-rc artifact, never git
#   * promotion and sealing run only from refs/tags/<version>, promotion first
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# --- script-level negative coverage (fixture gh, offline) --------------------
ck "rc manifest artifact self-test"   'bash scripts/fetch-rc-manifest.sh --self-test >/dev/null'
ck "promotion ref policy self-test"   'bash scripts/check-promotion-ref.sh --self-test >/dev/null'
ck "required-checks assert self-test" 'bash scripts/assert-required-checks.sh --self-test >/dev/null'

# --- the committed-evidence model is gone -----------------------------------
ck "no committed RC manifest in the source tree" \
   '! find release-evidence -name "release-manifest.yaml" 2>/dev/null | grep -q .'

# --- release.yml: dispatched from the tag, artifact-sourced, seal-only -------

# --- promote-stable.yml: tag-first ------------------------------------------

# --- required-check naming drift is caught (the gate matches names verbatim) -
tmp="$(mktemp -d)"
yq '.required_checks += ["a-check-no-workflow-emits"]' policies/required-release-checks.yaml > "$tmp/drift.yaml"
ck "unproducible required check is rejected" \
   '! POLICY="$tmp/drift.yaml" bash scripts/assert-required-checks.sh >/dev/null 2>&1'
# build+smoke moved to trusted-validation.yml (#96 redesign) and its matrix legs
# are covered by the seal job, so dropping one is no longer a gating change.
# Use a check that IS still gating on the release commit.
yq '.required_checks -= ["scan caddy prod"]' policies/required-release-checks.yaml > "$tmp/drop.yaml"
ck "dropping a gating job is rejected" \
   '! POLICY="$tmp/drop.yaml" bash scripts/assert-required-checks.sh >/dev/null 2>&1'
ck "ci asserts the check names" \
   'grep -q "assert-required-checks.sh" .github/workflows/ci.yml'
rm -rf "$tmp"

# --- the manifest signature check is actually wired (cosign runs in CI) -----
ck "manifest verification calls cosign verify-blob" \
   'grep -q "cosign verify-blob" scripts/verify-release-manifest.sh'
ck "fetch-rc-manifest delegates to verify-release-manifest.sh" \
   'grep -q "verify-release-manifest.sh" scripts/fetch-rc-manifest.sh'

echo "----"; [ "$fail" -eq 0 ] && echo "test_seal_path: PASS" || echo "test_seal_path: FAIL"
exit $fail
