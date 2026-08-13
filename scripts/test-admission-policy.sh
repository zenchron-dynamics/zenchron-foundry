#!/usr/bin/env bash
# =============================================================================
# scripts/test-admission-policy.sh — evaluate the admission policies with the
# REAL Kyverno engine, against compliant and violating fixtures (#124).
#
# Positive controls first, deliberately. A policy that denies everything passes
# every negative test and is worthless, so the compliant Pod must be ADMITTED
# before any rejection counts for anything.
#
# Needs docker (pinned Kyverno CLI), so it is not part of the offline suite.
# tests/governance/test_admission_policy.sh covers what can be checked without
# an engine: that the generated policies match their sources, and that every
# rule the issue names is present.
#
# THE BUG THIS CAUGHT. The digest-pinning and repository rules originally lived
# in the same file as the signature rules. Kyverno SKIPS a whole policy file when
# any rule in it needs registry credentials, so those two rules never evaluated —
# they were passing in the worst possible way, by not running. Splitting the
# files is what made them testable.
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1
POL="policy/kubernetes"
KYVERNO_IMAGE="ghcr.io/kyverno/kyverno-cli:v1.13.4"

pass=0; fail=0
ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

kyv() { docker run --rm --platform linux/amd64 -v "$ROOT:/w" -w /w "$KYVERNO_IMAGE" "$@"; }

# verdict <resource> <policies...> -> "pass:N fail:M", or "ERROR"
verdict() {
  local res="$1"; shift
  local out
  out="$(kyv apply "$@" --resource "$res" 2>&1)" || true
  # A SKIPPED policy is not a pass. It is the failure mode that hid two broken
  # rules, so it is surfaced as its own verdict rather than folded into "0 fail".
  if grep -q "Policies Skipped" <<<"$out"; then echo "SKIPPED"; return; fi
  grep -oE "pass: [0-9]+, fail: [0-9]+" <<<"$out" | tail -1 | tr -d ','
}

command -v docker >/dev/null 2>&1 || { echo "REFUSE: docker is required" >&2; exit 1; }
docker image inspect "$KYVERNO_IMAGE" >/dev/null 2>&1 || docker pull --platform linux/amd64 -q "$KYVERNO_IMAGE" >/dev/null

EVALUABLE="$POL/kyverno-image-provenance.yaml $POL/kyverno-runtime.yaml"

echo "== positive control: a compliant Pod must be ADMITTED"
# shellcheck disable=SC2086
V="$(verdict "$POL/tests/compliant.yaml" $EVALUABLE)"
ck "the compliant Pod passes every evaluable rule ($V)" \
   "[ \"\${V##*fail: }\" = 0 ]"
ck "...and it was not SKIPPED (a skipped policy proves nothing)" \
   "[ '$V' != SKIPPED ]"
ck "...and it actually evaluated rules rather than matching none" \
   "[ \"\$(printf '%s' '$V' | sed -E 's/pass: ([0-9]+).*/\\1/')\" -ge 8 ]"

echo
echo "== negative controls: each violation must be REJECTED"
for f in "$POL"/tests/violation-*.yaml; do
  n="$(basename "$f" .yaml)"; n="${n#violation-}"
  # shellcheck disable=SC2086
  V="$(verdict "$f" $EVALUABLE)"
  ck "$n is rejected ($V)" "[ '$V' != SKIPPED ] && [ \"\${V##*fail: }\" -ge 1 ]"
done

echo
echo "== the signature policy is structurally valid, even though it needs a registry"
# It cannot be EVALUATED offline; that is a property of verifyImages, not a gap
# we are hiding. What is checkable is that it parses and names both production
# identities and neither the candidate one.
ck "the signature policy parses as a Kyverno ClusterPolicy" \
   "python3 -c \"
import yaml; d=yaml.safe_load(open('$POL/kyverno-signatures.yaml'))
assert d['kind']=='ClusterPolicy' and d['spec']['rules']\""
ck "it requires BOTH sbom and provenance attestations" \
   "python3 -c \"
import yaml; d=yaml.safe_load(open('$POL/kyverno-signatures.yaml'))
types={a['type'] for r in d['spec']['rules'] for v in r.get('verifyImages',[]) for a in v.get('attestations',[])}
assert 'https://spdx.dev/Document' in types and 'https://slsa.dev/provenance/v1' in types, types\""
# THE requirement from the issue: a rebuild candidate must not satisfy production.
ck "a scheduled-rebuild identity does NOT satisfy the production policy" \
   "python3 -c \"
import re, yaml
ci = yaml.safe_load(open('policies/cosign-identities.yaml'))
d  = yaml.safe_load(open('$POL/kyverno-signatures.yaml'))
subs = [e['keyless']['subject']
        for r in d['spec']['rules'] for v in r.get('verifyImages', [])
        for a in v.get('attestors', []) for e in a['entries']]
cand = 'https://github.com/zenchron-dynamics/zenchron-foundry/.github/workflows/scheduled-rebuild.yml@refs/heads/master'
assert subs, 'no attestor subjects at all'
for s in subs:
    assert not re.match(s, cand), ('a rebuild candidate matches a production identity', s)
\""

echo "----"
printf 'admission policy: %d ok, %d failed\n' "$pass" "$fail"
[ "$fail" -eq 0 ]
