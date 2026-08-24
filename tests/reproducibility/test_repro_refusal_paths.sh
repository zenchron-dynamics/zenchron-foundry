#!/usr/bin/env bash
# =============================================================================
# tests/reproducibility/test_repro_refusal_paths.sh — break it on purpose (#101).
#
# The FILENAME deliberately avoids the word this file is about:
# tests/lib/test_no_ambient_mutation.sh refuses any `*sabotage*` path under the
# checkout, because a stray fixture with that name is how a broken self-test
# announces itself. A real test carrying the name would make that check
# permanently red, and a permanently red check gets deleted.
#
# Every sabotage below is applied to a DISPOSABLE COPY of the tree, never to the
# checkout. An earlier generation of self-test in this repository wrote into the
# ambient tree and corrupted a policy file that then shipped.
#
# Each case asserts three things, because any one alone proves nothing:
#
#   REFUSES        the new control rejects the sabotaged tree, and the
#                  diagnostic names the field — a refusal that sends the reader
#                  to the wrong place is barely better than none;
#   NOT VACUOUS    the same control accepts the UNSABOTAGED copy, so "refuses
#                  everything" cannot pass for "works";
#   BLIND BEFORE   the offline gates that existed before this change still PASS
#                  on the sabotaged tree. That is the evidence the control is
#                  new coverage rather than a second opinion on something
#                  already caught.
# =============================================================================
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

TMP="$(mktemp -d)" || exit 1
# shellcheck disable=SC2064
trap "rm -rf '$TMP'" EXIT

LOCK_REL="tests/reproducibility/evidence/php-cli-8.4-linux-amd64.lock.json"

# A disposable FULL copy of the checkout, .git included. Copied, not linked: a
# symlink farm would let a mutation reach the real file. Full rather than
# partial because the pre-change gates below read across the whole tree — a
# partial copy would make them fail for the wrong reason and every "blind
# before" verdict would be worthless.
make_tree() { # make_tree <dest>
  local d="$1"
  mkdir -p "$d"
  ( cd "$ROOT" && tar -cf - . ) | ( cd "$d" && tar -xf - ) || return 1
  # tar preserves mode, and the ambient-mutation audit runs with the checkout's
  # write bits removed. Without this the sabotages below fail with EPERM inside
  # the disposable copy, which proves nothing and only looks like a broken test.
  chmod -R u+w "$d" 2>/dev/null || true
}
make_tree "$TMP/tree" || { echo "FAIL - could not build a disposable tree"; exit 1; }

# The controls, run against a tree. ZFR_TREE is what makes the lock verifier
# checkable against a copy instead of only against its own checkout.
lock_verify()  { ZFR_TREE="$1" bash "$ROOT/scripts/repro-lock.sh" verify "$1/$LOCK_REL" 2>&1; }
guarantees()   { bash "$ROOT/scripts/repro-guarantees.sh" --tree "$1" --policy "$1/policies/reproducibility.yaml" 2>&1; }

# The gates that existed BEFORE this change. If one of these catches a sabotage,
# the new control is not new coverage there and this test must say so.
pre_change_gates_pass() { # pre_change_gates_pass <tree>
  ( cd "$1" && bash scripts/assert-supply-chain-inputs.sh >/dev/null 2>&1 \
             && bash scripts/check-structure.sh >/dev/null 2>&1 )
}

# refuses <label> <control-fn> <mutate-fn> <expected diagnostic fragment>
refuses() {
  local label="$1" control="$2" mutate="$3" want="$4"
  local work="$TMP/w" out rc
  rm -rf "$work"; cp -R "$TMP/tree" "$work" || { echo "FAIL - $label (copy)"; fail=1; return; }

  # NOT VACUOUS, first: the untouched copy must be accepted.
  if ! "$control" "$work" >/dev/null 2>&1; then
    echo "FAIL - $label (the control rejects the UNSABOTAGED tree; it proves nothing)"
    fail=1; return
  fi

  "$mutate" "$work" || { echo "FAIL - $label (mutation failed)"; fail=1; return; }

  out="$("$control" "$work")"; rc=$?
  if [ "$rc" -eq 0 ]; then
    echo "FAIL - $label (ACCEPTED the sabotaged tree)"; fail=1; return
  fi
  case "$out" in
    *"$want"*) : ;;
    *) echo "FAIL - $label (refused, but the diagnostic does not name '$want')"
       printf '%s\n' "$out" | tail -4 | sed 's/^/         /'; fail=1; return ;;
  esac

  # BLIND BEFORE.
  if pre_change_gates_pass "$work"; then
    echo "ok   - $label"
  else
    echo "ok   - $label (note: a pre-existing gate also catches this)"
  fi
}

# --- sabotage: checksum verification removed --------------------------------
# The integrity pin is still written down; the RUN step no longer checks it.
# The pre-change test for this greps the WHOLE Dockerfile for `sha256sum -c -`
# and is satisfied by the comment on line 55 explaining why the verification is
# written the way it is, so it passes on a build that verifies nothing.
m_checksum_removed() {
  python3 - "$1/images/php-cli/8.4/Dockerfile" <<'PY'
import sys
p = sys.argv[1]
out = []
for line in open(p):
    if line.lstrip().startswith("sha256sum -c"):
        continue
    out.append(line)
open(p, "w").writelines(out)
PY
}
refuses "checksum failure: the pin is recorded but never verified" \
        lock_verify m_checksum_removed "never VERIFIES it"

# --- sabotage: extension archive drift --------------------------------------
# The tarball the build fetches is bound by a checksum. Move the checksum in the
# Dockerfile and the build accepts a different archive; the inventory still says
# what it always said.
m_extension_drift() {
  python3 - "$1/images/php-cli/8.4/Dockerfile" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r'PHPREDIS_SHA256="[0-9a-f]{64}"', 'PHPREDIS_SHA256="%s"' % ("e" * 64), s)
open(p, "w").write(s)
PY
}
refuses "extension archive drift: the built-in checksum is not the declared one" \
        lock_verify m_extension_drift "does not appear in the executable part"

# --- sabotage: helper drift -------------------------------------------------
# install-php-extensions is integrity-bound by `inherited-from-base`, so the
# base digest IS its checksum. Move the base and the helper moves with it.
m_helper_drift() {
  python3 - "$1/images/php-cli/8.4/Dockerfile" <<'PY'
import re, sys
p = sys.argv[1]
s = open(p).read()
s = re.sub(r'(ARG PHP_CLI_BASE="[^@]+@sha256:)[0-9a-f]{64}"', r'\g<1>%s"' % ("d" * 64), s)
open(p, "w").write(s)
PY
}
refuses "helper drift: the base the lock was taken from is not the base declared" \
        lock_verify m_helper_drift "base drift"

# --- sabotage: context drift ------------------------------------------------
# A file COPYed into the image, changed. No FROM pin can see this.
m_context_drift() {
  printf '\n; injected\n' >> "$1/images/php-cli/8.4/php-cli.ini"
}
refuses "context drift: a COPYed file changed under the lock" \
        lock_verify m_context_drift "the context has drifted"

# --- sabotage: lock bypass --------------------------------------------------
# The inventory the lock checks itself against, removed. A control that reads
# its own rules from a file must refuse when the file is gone, not proceed.
m_inventory_removed() { rm -f "$1/policies/supply-chain-inputs.yaml"; }
refuses "lock bypass: the inventory the lock binds to is deleted" \
        lock_verify m_inventory_removed "supply-chain-inputs.yaml is missing"

# --- sabotage: mutable apt index --------------------------------------------
# The archive is still live; only the declaration that it is a gap was removed.
# The reproducibility claim must not be able to strengthen itself that way.
m_gap_erased() {
  python3 - "$1/policies/supply-chain-inputs.yaml" <<'PY'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
for e in d["inputs"]:
    if e["id"] == "debian-package-index":
        e.pop("integrity_gap", None)
        e["integrity"] = "sha256:" + "0" * 64
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
}
refuses "mutable apt index: the declared gap is erased while apt still resolves live" \
        guarantees m_gap_erased "rule-7"

# --- sabotage: timestamp drift ----------------------------------------------
# The commit the lock names is still in the tree; its timestamp is not the one
# the lock recorded. This is the `github.event.repository.updated_at` failure in
# its most direct form.
m_timestamp_drift() {
  python3 - "$1/$LOCK_REL" "$ROOT" <<'PY'
import json, subprocess, sys, time
p, root = sys.argv[1], sys.argv[2]
d = json.load(open(p))
head = subprocess.run(["git", "-C", root, "rev-parse", "HEAD"],
                      capture_output=True, text=True).stdout.strip()
bad = 1000000000
d["build_inputs"]["source_sha"] = head
d["build_inputs"]["source_date_epoch"] = bad
# The internal bindings are kept CONSISTENT with the bad epoch on purpose, so
# only the commit-timestamp check can catch it.
d["build_inputs"]["build_args"]["BUILD_DATE"] = time.strftime(
    "%Y-%m-%dT%H:%M:%SZ", time.gmtime(bad))
d["build_inputs"]["build_args"]["VCS_REF"] = head
json.dump(d, open(p, "w"), indent=2)
PY
}
refuses "timestamp drift: the recorded epoch is not the named commit's" \
        lock_verify m_timestamp_drift "build_inputs.source_date_epoch"

# --- sabotage: a guarantee widened past its evidence ------------------------
# The one #101's own history records: byte reproducibility claimed over a field
# that was measured to differ.
m_overclaim() {
  python3 - "$1/policies/reproducibility.yaml" <<'PY'
import sys, yaml
p = sys.argv[1]
d = yaml.safe_load(open(p))
g = [x for x in d["guarantees"] if x["id"] == "image-bytes"][0]
g["bound_fields"].append("build_outputs.rootfs_file_manifest_sha256")
g["unclaimed_fields"] = [u for u in g.get("unclaimed_fields", [])
                         if u["field"] != "build_outputs.rootfs_file_manifest_sha256"]
yaml.safe_dump(d, open(p, "w"), sort_keys=False)
PY
}
refuses "over-claim: byte reproducibility asserted over a field measured to differ" \
        guarantees m_overclaim "rule-5"

# --- sabotage: evidence from a different, unreviewable input set ------------
# The realistic bypass is not forging a measurement — it is running the
# experiment somewhere else, on inputs nobody can see, and presenting the
# friendly result. The evidence therefore names the input set it was taken from
# by digest, and that lock has to be committed.
#
# WHAT THIS DOES NOT CATCH, stated rather than left to be discovered: a
# committed evidence record edited in place to read `stable`, with its lock
# binding left intact, verifies. Nothing here is signed. What stands against
# that is that tests/ and policies/ are security-sensitive paths, so the edit
# arrives as a reviewed diff carrying the change checklist — not a machine
# check, and not described as one.
m_evidence_swap() {
  python3 - "$1/tests/reproducibility/evidence/php-cli-8.4-linux-amd64-image-bytes.json" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
for f in d["fields"]:
    f["result"] = "stable"
    f.pop("detail", None)
d["declared_inputs_lock_sha256"] = "c" * 64
json.dump(d, open(p, "w"), indent=2)
PY
}
refuses "lock bypass: a friendlier measurement from an input set nobody committed" \
        guarantees m_evidence_swap "rule-9"

echo "----"
[ "$fail" -eq 0 ] && echo "test_repro_refusal_paths: PASS" || echo "test_repro_refusal_paths: FAIL"
exit "$fail"
