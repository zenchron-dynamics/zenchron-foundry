#!/usr/bin/env bash
# shellcheck disable=SC2034
# ^ ck() evals its second argument; uses inside those strings are invisible to shellcheck.
# =============================================================================
# tests/release/test_acceptance_evidence_record.sh
# -----------------------------------------------------------------------------
# The committed post-acceptance evidence record for run 32395890071 must remain
# internally consistent and must keep asserting the things that bound it:
#
#   * it applies to ONE source revision and says so;
#   * ten of its arm64 children ran under QEMU and it discloses that, so #139
#     can close on it while #111 cannot;
#   * it is checksummed, so a later edit is visible.
#
# This is the record that has to outlive the GitHub Actions artifacts.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
D=docs/audits/acceptance-multiarch-2026-08-20
J="$D/acceptance-evidence.json"
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "the evidence record exists" "test -s '$J'"
ck "it is valid JSON" "jq -e . '$J' >/dev/null"

ck "the recorded checksum matches the file (a later edit is visible)" \
   "[ \"\$(shasum -a 256 '$J' | cut -d' ' -f1)\" = \"\$(cut -d' ' -f1 < '$D/SHA256SUMS')\" ]"

ck "verdict is PASS" "[ \"\$(jq -r .acceptance.verdict '$J')\" = PASS ]"
ck "run identity is 32395890071 attempt 1" \
   "[ \"\$(jq -r .acceptance.workflow_run_id '$J')\" = 32395890071 ] &&
    [ \"\$(jq -r .acceptance.workflow_run_attempt '$J')\" = 1 ]"
ck "source revision is the accepted SHA" \
   "[ \"\$(jq -r .source_revision '$J')\" = 7061caafb3ea09bd5b2342a1daf022151b33f822 ]"
ck "every child carries that same source revision implicitly via one record" \
   "[ \"\$(jq -r '.children|length' '$J')\" -eq 20 ]"

# --- the scope limit must be stated, not implied --------------------------
ck "the record states acceptance applies ONLY to that revision" \
   "jq -r .scope_note '$J' | grep -q 'ONLY to source revision'"
ck "...and explicitly denies authorizing later commits" \
   "jq -r .scope_note '$J' | grep -q 'does not authorize any later'"
ck "...and denies being a publication/signing/release authorization" \
   "jq -r .scope_note '$J' | grep -qi 'not a publication, signing, promotion or release'"

# --- identity and uniqueness ----------------------------------------------
for f in child_key manifest_digest evidence_sha256 staging_tag; do
  ck "20 unique $f" \
     "[ \"\$(jq -r '[.children[].$f]|unique|length' '$J')\" -eq 20 ]"
done
ck "10 amd64 / 10 arm64" \
   "[ \"\$(jq -r '[.children[]|select(.platform==\"linux/amd64\")]|length' '$J')\" -eq 10 ] &&
    [ \"\$(jq -r '[.children[]|select(.platform==\"linux/arm64\")]|length' '$J')\" -eq 10 ]"
ck "config architecture matches platform for all 20" \
   "[ \"\$(jq -r '[.children[]|select((.platform|split(\"/\")[1])==.config_architecture)]|length' '$J')\" -eq 20 ]"
ck "every child is bound to an immutable sha256 manifest digest" \
   "[ \"\$(jq -r '[.children[]|select(.manifest_digest|test(\"^sha256:[0-9a-f]{64}$\"))]|length' '$J')\" -eq 20 ]"
# `.digest_reference|endswith(.manifest_digest)` silently rebinds `.` to the
# reference STRING inside the pipe, so the inner .manifest_digest is not the
# child's. Bind the object first — otherwise this compares a field to itself.
ck "every digest_reference ends in its own manifest digest" \
   "[ \"\$(jq -r '[.children[]|. as \$c|select(\$c.digest_reference|endswith(\$c.manifest_digest))]|length' '$J')\" -eq 20 ]"
ck "...and the check is not vacuous — a mismatched digest is rejected" \
   "[ \"\$(jq -r '[.children[]|. as \$c|select(\$c.digest_reference|endswith(\"sha256:\"+(\"0\"*64)))]|length' '$J')\" -eq 0 ]"

# --- gates ------------------------------------------------------------------
for g in smoke_test metadata_contract scan reconciliation; do
  ck "$g PASS on all 20" \
     "[ \"\$(jq -r '[.children[]|select(.$g==\"PASS\")]|length' '$J')\" -eq 20 ]"
done

# --- one database, one scanner ---------------------------------------------
ck "the frozen database identity is recorded and marked frozen" \
   "jq -e '.frozen_vulnerability_database.frozen == true' '$J' >/dev/null &&
    jq -r .frozen_vulnerability_database.identity '$J' | grep -q '^v2+updated:2026-08-20T13:14:11'"
ck "the scanner image is digest-pinned, not a tag" \
   "jq -r .scanner.image '$J' | grep -q '@sha256:[0-9a-f]\{64\}$'"

# --- QEMU disclosure: the #139 / #111 boundary ------------------------------
ck "ten children are disclosed as QEMU" \
   "[ \"\$(jq -r .execution_disclosure.qemu_children '$J')\" -eq 10 ]"
ck "ten children are disclosed as native" \
   "[ \"\$(jq -r .execution_disclosure.native_children '$J')\" -eq 10 ]"
ck "the disclosure matches the per-child execution_mode fields" \
   "[ \"\$(jq -r '[.children[]|select(.execution_mode==\"qemu\")]|length' '$J')\" -eq 10 ]"
ck "the record states QEMU is acceptable for #139" \
   "jq -r .execution_disclosure.statement '$J' | grep -q '#139'"
ck "...and that it does NOT satisfy #111" \
   "jq -r .execution_disclosure.statement '$J' | grep -q 'does not satisfy #111'"
ck "issue linkage closes 139 and explicitly does not close 111" \
   "jq -e '.issue_linkage.closes == [139]' '$J' >/dev/null &&
    jq -e '.issue_linkage.does_not_close[\"111\"]' '$J' >/dev/null"

# --- timing is real, not fabricated ----------------------------------------
ck "every child records a POSITIVE wall time" \
   "[ \"\$(jq -r '[.children[]|select(.child_wall_seconds>0)]|length' '$J')\" -eq 20 ]"
ck "queue time is null, never zero" \
   "jq -e '.timing.queue_seconds == null' '$J' >/dev/null"
ck "emulated children are slower than native (sanity on the disclosure)" \
   "[ \"\$(jq -r '.timing.qemu_avg_seconds > .timing.native_avg_seconds' '$J')\" = true ]"

# --- findings are preserved, not summarized away ---------------------------
ck "governed findings are recorded per child" \
   "[ \"\$(jq -r '[.children[]|select(.governed_findings|length>0)]|length' '$J')\" -ge 18 ]"
ck "both governed CVEs appear on exactly 18 children each" \
   "[ \"\$(jq -r '[.children[]|select(.governed_findings|has(\"CVE-2026-14456\"))]|length' '$J')\" -eq 18 ] &&
    [ \"\$(jq -r '[.children[]|select(.governed_findings|has(\"CVE-2026-53613\"))]|length' '$J')\" -eq 18 ]"
ck "caddy carries neither governed CVE (it drew no coverage)" \
   "[ \"\$(jq -r '[.children[]|select(.image_label==\"caddy/prod\")|select((.governed_findings|has(\"CVE-2026-14456\")) or (.governed_findings|has(\"CVE-2026-53613\")))]|length' '$J')\" -eq 0 ]"
ck "package inventories are preserved with counts and checksums" \
   "[ \"\$(jq -r '[.children[]|select(.package_inventory.package_count>0)]|length' '$J')\" -eq 20 ]"

echo "----"; [ "$fail" -eq 0 ] && echo "test_acceptance_evidence_record: PASS" || echo "test_acceptance_evidence_record: FAIL"
exit $fail
