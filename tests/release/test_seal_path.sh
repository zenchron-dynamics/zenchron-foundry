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

# --- the committed-evidence model is gone -----------------------------------
ck "release.yml does not read committed release-evidence/" \
   '! grep -q "release-evidence/" .github/workflows/release.yml'
ck "no committed RC manifest in the source tree" \
   '! find release-evidence -name "release-manifest.yaml" 2>/dev/null | grep -q .'

# --- release.yml: dispatched from the tag, artifact-sourced, seal-only -------
ck "release.yml is dispatch-only (no tag-push auto-seal)" \
   'yq -e ".on | has(\"workflow_dispatch\") and (has(\"push\") | not)" .github/workflows/release.yml >/dev/null'
ck "release.yml takes the publish-rc run id" \
   'yq -e ".on.workflow_dispatch.inputs | keys | contains([\"version\",\"rc\",\"rc_manifest_run_id\"])" .github/workflows/release.yml >/dev/null'
ck "release.yml enforces the stable-tag ref policy" \
   'grep -q "check-promotion-ref.sh" .github/workflows/release.yml'
ck "release.yml fetches the signed RC manifest artifact" \
   'grep -q "fetch-rc-manifest.sh" .github/workflows/release.yml'
ck "release.yml verifies stable aliases == RC digests" \
   'grep -q "verify-release-binding.sh" .github/workflows/release.yml'
ck "release.yml keeps the exact-commit CI gate" \
   'grep -q "check-exact-commit-ci.sh" .github/workflows/release.yml'
ck "release.yml still performs no docker build" \
   '! grep -v "^ *#" .github/workflows/release.yml | grep -Eq "docker build|buildx build"'
ck "release.yml can read artifacts (actions: read)" \
   'yq -e ".jobs.guard.permissions.actions == \"read\" and .jobs.release.permissions.actions == \"read\"" .github/workflows/release.yml >/dev/null'

# --- promote-stable.yml: tag-first ------------------------------------------
ck "promote-stable.yml enforces the stable-tag ref policy" \
   'grep -q "check-promotion-ref.sh" .github/workflows/promote-stable.yml'
ck "promote-stable.yml binds tag commit to expected_revision" \
   'grep -q "tag commit \$SHA != expected_revision" .github/workflows/promote-stable.yml'
ck "promote-stable.yml fetches the RC manifest through the verifier" \
   'grep -q "fetch-rc-manifest.sh" .github/workflows/promote-stable.yml'
ck "promote-stable.yml keeps the production environment gate" \
   'yq -e ".jobs.gate.environment == \"foundry-production\"" .github/workflows/promote-stable.yml >/dev/null'
ck "promote-stable.yml still performs no docker build (comments aside)" \
   '! grep -v "^ *#" .github/workflows/promote-stable.yml | grep -Eq "docker build|buildx build"'

# --- the manifest signature check is actually wired (cosign runs in CI) -----
ck "manifest verification calls cosign verify-blob" \
   'grep -q "cosign verify-blob" scripts/verify-release-manifest.sh'
ck "fetch-rc-manifest delegates to verify-release-manifest.sh" \
   'grep -q "verify-release-manifest.sh" scripts/fetch-rc-manifest.sh'

echo "----"; [ "$fail" -eq 0 ] && echo "test_seal_path: PASS" || echo "test_seal_path: FAIL"
exit $fail
