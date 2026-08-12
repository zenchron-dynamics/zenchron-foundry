#!/usr/bin/env bash
# =============================================================================
# tests/lib/test_supply_chain_inputs.sh — the input inventory and its two
# consumers, offline (#101, #123).
#
# The executable reproducibility experiment needs docker and runs via
# `make reproducibility`. This is the offline half: the inventory is complete,
# every declared input is bound by a checksum or a digest, the inventory and the
# code agree, and the automation that watches them is wired up.
#
# The defect: Dependabot parses Dockerfile FROM lines and Actions refs. It does
# not parse `pecl install "redis-${VER}"`, which was version-pinned and
# integrity-unpinned — pecl resolved and downloaded the tarball itself, so the
# build trusted whatever pecl.php.net served at that instant. Nothing in the
# repository could notice that, or that the Trivy deciding whether a release
# ships had gone months out of date.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "the supply-chain verifier self-test passes" \
   "bash scripts/assert-supply-chain-inputs.sh --self-test >/dev/null"
ck "the real inventory passes its own integrity check" \
   "bash scripts/assert-supply-chain-inputs.sh >/dev/null"
ck "the reproducibility harness self-test passes" \
   "bash scripts/reproducibility-check.sh --self-test >/dev/null"

# --- the inventory covers what it claims to cover ---------------------------
ck "every input declares an owner and an update signal" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/supply-chain-inputs.yaml\"))
bad = [e[\"id\"] for e in d[\"inputs\"] if not e.get(\"owner\") or not e.get(\"update_signal\")]
assert not bad, bad
"'
ck "every input has an integrity binding or a DECLARED gap" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/supply-chain-inputs.yaml\"))
bad = [e[\"id\"] for e in d[\"inputs\"]
       if not (str(e.get(\"integrity\",\"\")).startswith(\"sha256:\")
               or e.get(\"integrity\") == \"inherited-from-base\"
               or e.get(\"integrity_gap\") is True)]
assert not bad, bad
"'
# The classes the issue named must actually be present. A complete-looking
# inventory that quietly omits a category is the failure mode here.
for id in phpredis install-php-extensions trivy hadolint shellcheck semgrep \
          gitleaks gh-cli jq yq frankenphp-go-modules debian-package-index; do
  ck "the inventory covers '$id'" \
     "python3 -c \"
import yaml
d = yaml.safe_load(open('policies/supply-chain-inputs.yaml'))
assert '$id' in [e['id'] for e in d['inputs']]\""
done

# --- #101: the fixes the inventory declares must actually be in the code ----
ck "the PECL tarball is fetched and CHECKSUMMED, not resolved by pecl" \
   'for f in images/php-cli/8.4/Dockerfile images/php-fpm/8.4/Dockerfile images/php-worker/8.4/Dockerfile; do
      grep -q "sha256sum -c -" "$f" || exit 1
      grep -q "pecl install /tmp/redis.tgz" "$f" || exit 1
      grep -qE "pecl install \"redis-" "$f" && exit 1
    done; true'
ck "the declared PECL checksum is the one the Dockerfiles use" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/supply-chain-inputs.yaml\"))
e = [x for x in d[\"inputs\"] if x[\"id\"] == \"phpredis\"][0]
sha = e[\"integrity\"].split(\":\",1)[1]
for f in e[\"declared_in\"]:
    assert sha in open(f).read(), f
"'
ck "no workflow derives a build timestamp from repository metadata" \
   "! grep -rn 'repository.updated_at' .github/workflows/ | grep -v '^\S*:[0-9]*: *#' | grep -q ."
ck "both build paths derive SOURCE_DATE_EPOCH from the source commit" \
   'for f in .github/workflows/build-images.yml .github/workflows/stage-and-authorize.yml; do
      grep -q "git log -1 --format=%ct" "$f" || exit 1
    done; true'
ck "build residue is removed rather than shipped" \
   'for f in images/nginx/Dockerfile images/php-cli/8.4/Dockerfile; do
      grep -q "/var/cache/ldconfig/aux-cache" "$f" || exit 1
    done; true'

# --- #123: the update signal is automated, and cannot silently stop ---------
ck "a scheduled workflow runs the drift detector" \
   "test -f .github/workflows/dependency-drift.yml && grep -q 'assert-supply-chain-inputs.sh --check-upstream' .github/workflows/dependency-drift.yml"
ck "...on a schedule, not only on demand" \
   "grep -q 'schedule:' .github/workflows/dependency-drift.yml"
ck "...and it verifies the inventory BEFORE trusting it" \
   "grep -q 'Verify the inventory before trusting it' .github/workflows/dependency-drift.yml"
# issues:write is the only write it gets. A cron job that can change a pin is a
# cron job that can weaken a gate without review.
ck "the drift workflow cannot write anything but issues" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\".github/workflows/dependency-drift.yml\"))
assert d[\"permissions\"] == {\"contents\": \"read\", \"issues\": \"write\"}, d[\"permissions\"]
"'
ck "the offline integrity check is wired into macro-validate" \
   "grep -q 'assert-supply-chain-inputs.sh' scripts/macro-validate.sh"
ck "#79's bundled Go modules are tracked as an input, not just an issue" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/supply-chain-inputs.yaml\"))
e = [x for x in d[\"inputs\"] if x[\"id\"] == \"frankenphp-go-modules\"][0]
assert e.get(\"tracked_issue\") == 79, e
assert e.get(\"tracked_findings\"), e
"'

# --- the honest gap ---------------------------------------------------------
# The Debian index is NOT pinned. It must be declared as a gap, with a note, and
# the reproducibility claim must not pretend otherwise.
ck "the Debian package index is declared as an integrity GAP" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/supply-chain-inputs.yaml\"))
e = [x for x in d[\"inputs\"] if x[\"id\"] == \"debian-package-index\"][0]
assert e[\"integrity_gap\"] is True and e[\"integrity\"] == \"none\", e
assert e.get(\"note\"), \"a gap must explain itself\"
"'
ck "the excluded nondeterminism is declared UP FRONT, not after a failure" \
   'python3 -c "
import yaml
d = yaml.safe_load(open(\"policies/supply-chain-inputs.yaml\"))
kn = d[\"build_determinism\"][\"known_nondeterminism\"]
assert kn and all(\"reason\" in k for k in kn), kn
"'

echo "----"; [ "$fail" -eq 0 ] && echo "test_supply_chain_inputs: PASS" || echo "test_supply_chain_inputs: FAIL"
exit $fail
