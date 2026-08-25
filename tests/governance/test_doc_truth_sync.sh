#!/usr/bin/env bash
# =============================================================================
# tests/governance/test_doc_truth_sync.sh — authoritative documents must not
# contradict the code they describe (#121).
#
# Each case below pairs a CLAIM in a document with the FACT in workflow,
# Dockerfile or policy source that decides whether the claim is true, and derives
# the expectation from the fact. It does not restate the expected wording as a
# literal, because that only moves the drift from the document into the test.
#
# Why this is worth a gate. Every mismatch found while writing this file
# understated or misdescribed a control that had been *strengthened*:
#
#   * vulnerability-management.md said the gate uses `--ignore-unfixed` and that
#     nginx and caddy are "scan-and-report (non-gating)". Both stopped being true
#     in #102/#103 and #136. An auditor reading the document would have concluded
#     the platform ignores unfixed CVEs and does not gate its edge images —
#     the opposite of what runs.
#   * it also described scanning "a saved image tar"; the scan mounts the Docker
#     socket and scans the built image.
#   * threat-model.md credited a `cgi-fcgi` healthcheck that was never shipped in
#     the Debian images.
#   * legacy-php-policy.md described a CI scan, a `legacy: true` matrix flag and
#     a monthly Dependabot watch for images whose source was deleted — directly
#     contradicting its own "Frozen" section two paragraphs above.
#   * repository-security.md said "No org teams exist yet"; both teams exist (and
#     both have the same single member, which is the fact that actually matters).
#
# Runs offline. No docker, no network, no GitHub API.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

SCAN=.github/workflows/scan-images.yml
VM=docs/vulnerability-management.md

# `code_of <file>` strips comment lines, so a document quoting a control it no
# longer has — or a workflow explaining a deleted one — is not mistaken for the
# control being present.
uncommented() { grep -vE '^[[:space:]]*#' "$1"; }

# --- the enforcing gate -----------------------------------------------------
# FACT: the workflow passes neither --ignore-unfixed nor --ignorefile.
ck "FACT: the scan suppresses nothing before the ledger is consulted" \
   "! uncommented $SCAN | grep -qE -- '--ignore-unfixed|--ignorefile'"
# CLAIM: therefore no document may say the gate ignores unfixed findings.
# Mentions that RETRACT the behaviour are fine and are what a reader needs; a
# mention that still ASSERTS it is the defect. Dated triage records under
# docs/security/triage-*.md describe the state at the time they were written and
# are excluded, as are the audit archives.
#
# NOT written as `! grep ... | grep -q .`. Under `pipefail` the pipeline reports
# the FIRST command's status when it is non-zero, and some greps exit non-zero on
# a warning (a `--include` this build does not support). The negation then turned
# a real violation into a pass — this assertion was silently vacuous until the
# regression run against master showed it passing on documents that plainly still
# made the claim. Collect the offenders, then assert the list is empty.
stale_unfixed_claims() {
  grep -rn -- '--ignore-unfixed' docs --include='*.md' 2>/dev/null \
    | grep -vE 'docs/(audits|security/triage-)' \
    | grep -viE 'no longer|not filtered|not ignored|not excluded|used to|previously|removed|dropped every|stopped|was removed|is gone' \
    || true
}
ck "no doc still asserts the gate filters unfixed findings" \
   '[ -z "$(stale_unfixed_claims)" ]'

# FACT: the gate step is unconditional — there is no per-image gate flag, so a
# report-only image cannot be expressed.
ck "FACT: there is no per-image gate flag in the scan matrix" \
   "! grep -qE 'gate: *(true|false)|matrix\.gate' $SCAN"
# CLAIM: therefore no document may describe an image family as non-gating.
# Grype genuinely IS non-gating (second opinion), so that one line is allowed —
# matched on the scanner name, not exempted by file.
# Same shape as above, and for the same reason: collect, then assert empty.
# Grype genuinely IS non-gating (it is a second opinion), so that line is allowed
# — matched on the scanner name, not exempted by file.
stale_nongating_claims() {
  grep -rn 'non-gating' docs --include='*.md' 2>/dev/null \
    | grep -v 'docs/audits/' \
    | grep -viE 'grype|previously|used to|has not been true|stopped being true' \
    || true
}
ck "no doc describes an IMAGE as non-gating" '[ -z "$(stale_nongating_claims)" ]'

# FACT: trivy scans the daemon's image via the mounted socket.
ck "FACT: the scan mounts the docker socket and scans a built image" \
   "grep -q '/var/run/docker.sock' $SCAN && grep -q 'trivy.*image \"scan-target:' $SCAN"
ck "the vulnerability doc does not describe tar-file scanning" \
   "! grep -qiE 'saved image tar|image tar' $VM"

# --- healthcheck tooling ----------------------------------------------------
# FACT: no image installs an HTTP/FastCGI client for its healthcheck.
for df in images/php-fpm/8.4/Dockerfile images/php-frankenphp/8.4/Dockerfile images/nginx/Dockerfile; do
  ck "FACT: $df installs no cgi-fcgi" \
     "! uncommented $df | grep -qE '(^|[[:space:]])(fcgi|libfcgi-bin)([[:space:]]|;|\\\\|$)'"
done
# CLAIM: the threat model must not credit a cgi-fcgi healthcheck as a control.
threat_model_fcgi_claims() {
  grep -n 'cgi-fcgi' docs/threat-model.md 2>/dev/null \
    | grep -viE 'no |never|not shipped' || true
}
ck "the threat model does not credit a cgi-fcgi healthcheck" \
   '[ -z "$(threat_model_fcgi_claims)" ]'

# --- legacy lines -----------------------------------------------------------
# FACT: no legacy image source exists, and the matrix gate forbids it returning.
ck "FACT: no php-*/7.4 or php-*/8.0 source directory exists" \
   "[ -z \"\$(find images -type d -path '*/php-*/7.4' -o -type d -path '*/php-*/8.0')\" ]"
ck "FACT: assert-image-matrix.sh forbids the legacy lines" \
   "grep -q 'for legacy in 7.4 8.0' scripts/assert-image-matrix.sh"
# FACT: dependabot declares no legacy entry.
ck "FACT: dependabot watches no legacy base" \
   "! grep -qE '7\.4|8\.0' .github/dependabot.yml"
# CLAIM: the legacy policy must not claim CI scans them or Dependabot watches them.
legacy_scan_claims() {
  grep -nE 'legacy: true|CI \*\*scans\*\* legacy' docs/legacy-php-policy.md 2>/dev/null || true
}
legacy_dependabot_claims() {
  grep -n 'Dependabot watches legacy' docs/legacy-php-policy.md 2>/dev/null \
    | grep -viE 'does not|no ' || true
}
ck "the legacy policy does not claim a legacy CI scan or matrix flag" \
   '[ -z "$(legacy_scan_claims)" ]'
ck "the legacy policy does not claim Dependabot watches legacy bases" \
   '[ -z "$(legacy_dependabot_claims)" ]'

# --- ownership --------------------------------------------------------------
# FACT: CODEOWNERS routes to org teams, not to a personal handle.
ck "FACT: CODEOWNERS routes to org teams" \
   "grep -qE '@zenchron-dynamics/(platform|security)' CODEOWNERS"
# CLAIM: the security doc must not still say the teams do not exist.
ck "repository-security does not claim the org teams are missing" \
   "! grep -qi 'No org teams exist' docs/repository-security.md"
# ...and must not present Code Owner routing as independent review. #112 is the
# issue that owns the operating model; the document must point at it rather than
# imply a second reviewer exists.
ck "repository-security says routing is not segregation of duties" \
   "grep -qi 'not.*segregation of duties' docs/repository-security.md"

# --- ports ------------------------------------------------------------------
# FACT: frankenphp exposes 8080 and 8081 only; 8443 went with TLS termination.
ck "FACT: php-frankenphp exposes no 8443" \
   "! grep -qE '^EXPOSE .*8443' images/php-frankenphp/8.4/Dockerfile"
ck "its smoke test does not claim 8443 is exposed" \
   "! grep -q 'EXPOSE 8080 8443' scripts/smoke/smoke-php-frankenphp.sh"

# --- governance evidence citations ------------------------------------------
# FACT: the dated governance verification records live in docs/audits/ and are
# REPLACED, not appended to — governance-verification-2026-07-28.json was renamed
# away in e7c4e80 while five documents went on linking to it. A document that
# cites evidence which is not there is the #97 defect class exactly: a claim the
# repository does not carry. Derived from the tree, so it cannot rot into a
# literal.
governance_evidence_refs() {
  grep -rhoE 'governance-verification-[0-9]{4}-[0-9]{2}-[0-9]{2}\.json' \
    --include='*.md' . 2>/dev/null | sort -u
}
missing_governance_evidence() {
  local n
  while IFS= read -r n; do
    [ -n "$n" ] || continue
    [ -f "docs/audits/$n" ] || echo "$n"
  done < <(governance_evidence_refs)
}
# NON-VACUITY: the extractor must actually find citations, or the check below
# passes by finding nothing to check.
ck "NON-VACUOUS: documents do cite dated governance evidence" \
   '[ "$(governance_evidence_refs | wc -l)" -ge 1 ]'
ck "every cited governance-verification record exists in docs/audits/" \
   '[ -z "$(missing_governance_evidence)" ]'

# --- the PHP 8.5 release state: document vs machine-readable line -----------
#
# FACT: policies/lifecycle.yaml carries ONE foundry_release_state on the php-8.5
# line. CLAIM: docs/php-version-policy.md names a state for 8.5. They must be the
# SAME STRING, and the fact is read from the policy file rather than restated
# here, because restating it only moves the drift into this test.
#
# This pairing exists because both files were false at the same time and in the
# same direction: the document said `blocked-does-not-build` and "the failing
# component is not yet isolated" while the policy line already said
# `experimental-amd64-only` with `blocker.status: RESOLVED`. A reader of the
# document would have concluded the images cannot be built. They build.
PVP=docs/php-version-policy.md

lifecycle_php85_state() {
  python3 - <<'PYX'
import yaml
d = yaml.safe_load(open("policies/lifecycle.yaml"))
ln = [x for x in d["lines"] if x["id"] == "php-8.5"]
print(ln[0].get("foundry_release_state", "") if ln else "")
PYX
}

# doc_asserted_states <file> — every foundry_release_state value the document
# ASSERTS. Blockquoted lines are excluded: a retraction that quotes the value it
# withdraws is exactly what a reader who met the old value needs to find, and
# treating it as an assertion would make correcting a document impossible.
doc_asserted_states() {
  grep -vE '^[[:space:]]*>' "$1" \
    | grep -oE 'foundry_release_state:[[:space:]]*`?[a-z0-9.-]+' \
    | sed -E 's/.*foundry_release_state:[[:space:]]*`?//' \
    | LC_ALL=C sort -u
}

LIFE_STATE="$(lifecycle_php85_state)"
# Read by `ck`'s eval, which shellcheck cannot follow.
# shellcheck disable=SC2034
DOC_STATES="$(doc_asserted_states "$PVP")"

# NON-VACUITY, both sides. Either extractor returning nothing would make the
# comparison below pass by comparing emptiness with emptiness.
ck "NON-VACUOUS: policies/lifecycle.yaml carries a php-8.5 foundry_release_state" \
   '[ -n "$LIFE_STATE" ] && case "$LIFE_STATE" in *[!a-z0-9-]*) false ;; *) true ;; esac'
ck "NON-VACUOUS: $PVP asserts a foundry_release_state at all" '[ -n "$DOC_STATES" ]'
ck "the document states EXACTLY the lifecycle value, and only that one" \
   '[ "$DOC_STATES" = "$LIFE_STATE" ]'

# NON-VACUITY OF THE COMPARISON ITSELF, by mutation: a disposable copy whose
# value is flipped MUST be rejected. Without this the three assertions above
# would still pass if `doc_asserted_states` silently stopped matching anything
# but the empty-string guard happened to be satisfied by a different line.
# Writes only inside mktemp — never the checkout (tests/lib/test_no_ambient_mutation.sh).
DTMP="$(mktemp -d)"
# shellcheck disable=SC2064
trap "rm -rf '$DTMP'" EXIT
sed -E "s/foundry_release_state:[[:space:]]*${LIFE_STATE}/foundry_release_state: shipped-everywhere/g" \
    "$PVP" > "$DTMP/sabotaged.md"
ck "SABOTAGE: a document naming a DIFFERENT state is detected" \
   '[ "$(doc_asserted_states "$DTMP/sabotaged.md")" != "$LIFE_STATE" ]'
ck "...and the sabotage really changed the file (the probe is not a no-op)" \
   '! cmp -s "$PVP" "$DTMP/sabotaged.md"'

# The RETIRED value may appear only as a withdrawal. Anywhere it is still
# asserted, a reader is told the 8.5 images do not build — they do, on amd64.
# A blockquoted markdown line, a shell/YAML comment, this test itself, the dated
# audit archives and the changelog are all RECORDS of the retired value, not
# assertions of it. Everything else that still carries the string is telling a
# reader the 8.5 images do not build.
#
# The per-file body is CAPTURED and matched with `case`, never piped into
# `grep -q`: under `pipefail` a quiet matcher exits early, kills the producer
# with SIGPIPE and yields 141, which this file has already been bitten by.
retired_state_asserted() {
  local f body self
  self="./${0#./}"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    case "$f" in
      ./docs/audits/*|./CHANGELOG.md|"$self"|./tests/governance/test_doc_truth_sync.sh) continue ;;
    esac
    body="$(grep -vE '^[[:space:]]*[>#]' "$f")"
    # The KEY must be present, not merely the string. Prose that names the
    # retired value while withdrawing it ("...carried over from the withdrawn
    # blocked-does-not-build state") is a record; `foundry_release_state:
    # blocked-does-not-build` is an assertion. Matched from a HERE-STRING, never
    # a pipe, because a quiet matcher on a pipe exits early and returns 141.
    grep -qE 'foundry_release_state:[[:space:]]*`?blocked-does-not-build' <<<"$body" \
      && echo "$f"
  done < <(grep -rl 'blocked-does-not-build' --include='*.md' --include='*.yaml' \
             --include='*.yml' --include='*.sh' . 2>/dev/null)
}
# NON-VACUITY: the sweep must actually be finding the retracted mentions, or the
# emptiness below means only that nothing anywhere mentions the value.
ck "NON-VACUOUS: the retired value IS still recorded somewhere (as a retraction)" \
   '[ -n "$(grep -rl "blocked-does-not-build" --include="*.md" --include="*.yaml" --include="*.sh" . 2>/dev/null)" ]'
# SABOTAGE: a file that ASSERTS the value (not blockquoted, not commented) must
# be reported. Written into the disposable fixture, then swept from there.
mkdir -p "$DTMP/live/docs" && printf 'foundry_release_state: blocked-does-not-build\n' > "$DTMP/live/docs/rot.md"
sabotage_hits() { ( cd "$DTMP/live" && retired_state_asserted ); }
ck "SABOTAGE: a document that still ASSERTS the retired value is reported" \
   '[ -n "$(sabotage_hits)" ]'
printf '> `foundry_release_state: blocked-does-not-build` was withdrawn\n' > "$DTMP/live/docs/rot.md"
ck "...but the same string inside a RETRACTION is not" '[ -z "$(sabotage_hits)" ]'

ck "no live document or script still asserts blocked-does-not-build" \
   '[ -z "$(retired_state_asserted)" ]'

echo "----"; [ "$fail" -eq 0 ] && echo "test_doc_truth_sync: PASS" || echo "test_doc_truth_sync: FAIL"
exit $fail
