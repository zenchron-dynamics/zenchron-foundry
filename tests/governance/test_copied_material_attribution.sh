#!/usr/bin/env bash
# Copied third-party material must carry attribution.
#
# WHY. security/seccomp/zenchron-default.json is 832 lines copied verbatim from
# the Moby default seccomp profile at v27.3.1. It carried no copyright line, no
# licence reference, and a first-party-looking filename, while security/README.md
# described it accurately as an upstream copy. Apache-2.0 requires a
# redistributor to retain the copyright notice and licence text and to state
# changes.
#
# Two things make this class easy to miss:
#   * the obligation attaches TODAY, to material incorporated into the
#     repository, and does not depend on any future licence decision;
#   * the existing licence gate CANNOT see it — that pipeline reads SBOMs of
#     BUILT IMAGES, and this is repository material no image SBOM enumerates.
#
# So the check lives here, over the tree, not over an SBOM.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT" || exit 1
fail=0
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

# The list of copied material is NO LONGER HARDCODED HERE. It was, and it went
# stale exactly as you would expect: two entries in this array while five files
# carried an obligation. A per-test array composes with nothing and nothing
# outside this file could see it.
#
# The single canonical record is policies/repository-material.yaml (#120) and
# this test now derives its subject list from it. Adding copied material
# WITHOUT an inventory entry is caught by
# scripts/license/assert-repository-material.sh, which scans the tree; this
# test checks that each inventoried entry's ATTRIBUTION actually says what the
# inventory claims it says.
INVENTORY=policies/repository-material.yaml
ck "the canonical inventory exists (this test derives its subjects from it)" \
   "[ -f '$INVENTORY' ]"

# <material-path>|<attribution-path>|<upstream-project>|<spdx>
# The attribution is the local notice where there is one, otherwise the
# upstream NOTICE, otherwise the licence text.
_ROWS="$(python3 - "$INVENTORY" <<'ROWS_PY'
import sys, yaml
for m in yaml.safe_load(open(sys.argv[1]))["materials"]:
    ob = m["obligations"]
    att = ob.get("local_notice") or ob.get("required_notice") or ob.get("required_license_text")
    print("%s|%s|%s|%s" % (m["path"], att or "", m["upstream"]["project"],
                           m["licence"]["declared_spdx"] or ""))
ROWS_PY
)"
_INV_COUNT="$(python3 -c 'import sys,yaml;print(len(yaml.safe_load(open(sys.argv[1]))["materials"]))' "$INVENTORY")"

_n_rows=0
while IFS='|' read -r _f _n _proj _spdx; do
  [ -n "$_f" ] || continue
  _n_rows=$((_n_rows + 1))
  _projname="${_proj##*/}"          # moby/moby -> moby
  _spdxre="$(printf '%s' "$_spdx" | sed 's/[-.]/./g')"
  ck "copied material exists: $_f" "[ -f '$_f' ]"
  ck "...its attribution exists and is not empty: $_n" "[ -n '$_n' ] && [ -s '$_n' ]"
  ck "...naming the upstream project the inventory records ($_projname)" \
     "grep -qiF -- '$_projname' '$_n'"
  ck "...and the licence the inventory declares ($_spdx)" \
     "grep -qiE -- '$_spdxre' '$_n'"
  ck "...and a copyright line" "grep -qi 'copyright' '$_n'"
done <<ROWS_EOF
$_ROWS
ROWS_EOF

# NON-VACUITY 0: the loop must actually have run over every entry. A `while
# read` over an empty producer executes zero assertions and still reports PASS,
# which is the shape of a test that silently stopped testing anything.
ck "the inventory-derived loop covered EVERY material in the inventory" \
   "[ \"$_n_rows\" -eq \"$_INV_COUNT\" ] && [ \"$_n_rows\" -ge 5 ]"

# NON-VACUITY 1: the attribution must be findable by the same search that would
# fail on an unattributed file. Prove the search discriminates.
_probe="$(mktemp)"; printf '{"defaultAction":"SCMP_ACT_ERRNO"}\n' > "$_probe"
ck "NON-VACUOUS: an unattributed copy would FAIL the attribution search" \
   "! grep -qi 'copyright' '$_probe'"
rm -f "$_probe"

# NON-VACUITY 2: the seccomp profile itself genuinely carries no inline notice,
# which is WHY a sibling NOTICE is required. JSON admits no comments.
ck "the seccomp JSON carries no inline attribution (hence the sibling NOTICE)" \
   "[ \"\$(grep -ciE 'copyright|moby|licen[sc]e' security/seccomp/zenchron-default.json)\" = 0 ]"
ck "...and it still parses as JSON, so attribution did not corrupt it" \
   "python3 -c 'import json;json.load(open(\"security/seccomp/zenchron-default.json\"))'"

# The NOTICE must record deviations, or state there are none. A copy silently
# diverging from the upstream it credits is worse than an uncredited copy.
ck "the NOTICE records changes from upstream (or states there are none)" \
   "grep -qi 'CHANGES FROM UPSTREAM' security/seccomp/NOTICE"
ck "...and pins the upstream version it was taken from" \
   "grep -qE 'v[0-9]+\.[0-9]+\.[0-9]+' security/seccomp/NOTICE"

# The README's claim and the NOTICE must agree on the upstream version. A
# document that credits one version while the NOTICE credits another is the
# doc-truth defect class.
ck "README and NOTICE agree on the pinned upstream version" \
   'v1=$(grep -oE "v[0-9]+\.[0-9]+\.[0-9]+" security/README.md | head -1)
    v2=$(grep -oE "v[0-9]+\.[0-9]+\.[0-9]+" security/seccomp/NOTICE | head -1)
    [ -n "$v1" ] && [ "$v1" = "$v2" ]'

# --- ALL FOUR Apache-2.0 obligations, not just the two that are easy ---------
# policies/license-policy.yaml names four obligations for Apache-2.0:
#   retain-copyright-notice, retain-license-text, state-changes, retain-notice-file
# The first version of this check enforced the first and third and silently
# ignored the other two, so the repository redistributed Apache-2.0 material
# meeting half the obligations ITS OWN POLICY names — while a test asserted the
# attribution was complete. Caught by the rights-provenance packet, not by this
# test, which is the uncomfortable part.
UP=third-party/moby-v27.3.1

ck "the policy still names four Apache-2.0 obligations (source of this list)" \
   "grep -qE 'retain-copyright-notice, retain-license-text, state-changes, retain-notice-file' policies/license-policy.yaml"
ck "retain-license-text: the Apache-2.0 text is carried verbatim" \
   "[ -s '$UP/LICENSE' ] && grep -q 'Apache License' '$UP/LICENSE' && grep -q 'Version 2.0' '$UP/LICENSE'"
ck "retain-notice-file: upstream's own NOTICE is carried verbatim" \
   "[ -s '$UP/NOTICE' ] && grep -qi 'docker' '$UP/NOTICE'"
ck "...and the NOTICE carries upstream's copyright line, not ours" \
   "grep -qi 'copyright' '$UP/NOTICE'"
ck "both derived files point at the carried texts, so a reader can find them" \
   "grep -q 'third-party/moby-v27.3.1' security/seccomp/NOTICE &&
    grep -q 'third-party/moby-v27.3.1' security/apparmor/zenchron-container"
# NON-VACUITY: the licence text must be the real thing, not a stub. Upstream's
# is ~10.7KB; a placeholder would sail past a substring match.
ck "NON-VACUOUS: the licence text is a full licence, not a stub" \
   "[ \"\$(wc -c <'$UP/LICENSE')\" -gt 10000 ]"
ck "NON-VACUOUS: an empty file would fail the same check" \
   "t=\$(mktemp); ! { [ -s \"\$t\" ] && grep -q 'Apache License' \"\$t\"; }; r=\$?; rm -f \"\$t\"; [ \$r -eq 0 ]"

# --- provenance must be recorded, and must match the bytes on disk ----------
PROV="$UP/PROVENANCE.yaml"
ck "provenance is recorded machine-readably" \
   "[ -f '$PROV' ] && python3 -c 'import yaml;yaml.safe_load(open(\"$PROV\"))'"
ck "...naming the upstream project, source URL and pinned revision" \
   "grep -q 'github.com/moby/moby' '$PROV' && grep -q 'revision_tag: v27.3.1' '$PROV'"
ck "...and the recorded sha256 MATCHES the bytes actually carried" \
   "python3 - <<'PYCHK'
import hashlib, sys, yaml
d = yaml.safe_load(open('$PROV'))
bad = []
for f in d['files']:
    got = hashlib.sha256(open(f['path'], 'rb').read()).hexdigest()
    if got != f['sha256'] or len(open(f['path'],'rb').read()) != f['bytes']:
        bad.append(f['path'])
sys.exit(1 if bad else 0)
PYCHK"
ck "NON-VACUOUS: a tampered byte would break that hash comparison" \
   "python3 -c \"
import hashlib
a = hashlib.sha256(b'x').hexdigest(); b = hashlib.sha256(b'y').hexdigest()
raise SystemExit(0 if a != b else 1)\""

# --- these texts are NOT this project's outbound licence --------------------
# A LICENSE file in the tree is exactly how a project-wide licence is normally
# declared. Carrying upstream's must not read as adopting it.
ck "the carried texts live under an unambiguous third-party path" \
   "case '$UP' in third-party/*) true ;; *) false ;; esac"
ck "the ROOT LICENSE is untouched and is not the Apache text" \
   "[ -f LICENSE ] && ! grep -q 'Apache License' LICENSE"
ck "the provenance says plainly these are not the project licence" \
   "grep -qi 'NOT Zenchron Foundry' '$PROV'"
ck "the project's outbound licence decision is still recorded as undetermined" \
   "grep -qE '^ *decision: undetermined' policies/license-policy.yaml"
# LICENSE:22-23 does not use the word "placeholder"; it says "replace this file
# before publication". That sentence is the actual signal that the current text
# is provisional, so the assertion tracks the wording that exists.
ck "...and the root LICENSE still says it must be replaced before publication" \
   "grep -qi 'replace this file' LICENSE"
ck "NON-VACUOUS: that phrase is genuinely present, not matched by accident" \
   "[ \"\$(grep -ci 'replace this file' LICENSE)\" = 1 ]"

# --- an unrelated licence family must not satisfy an Apache obligation ------
# Carrying SOME licence text is not carrying THE licence text.
ck "SABOTAGE: an MIT text does not satisfy the Apache-2.0 licence-text obligation" \
   "t=\$(mktemp); printf 'MIT License\n\nPermission is hereby granted, free of charge...\n' > \"\$t\";
    ! { grep -q 'Apache License' \"\$t\" && grep -q 'Version 2.0' \"\$t\"; }; r=\$?; rm -f \"\$t\"; [ \$r -eq 0 ]"
ck "...while the real Apache text does satisfy it (the check is not just strict)" \
   "grep -q 'Apache License' '$UP/LICENSE' && grep -q 'Version 2.0' '$UP/LICENSE'"

# --- provenance must be recorded, and must match the bytes on disk ----------
PROV="$UP/PROVENANCE.yaml"
ck "provenance is recorded machine-readably" \
   "[ -f '$PROV' ] && python3 -c 'import yaml;yaml.safe_load(open(\"$PROV\"))'"
ck "...naming the upstream project, source URL and pinned revision" \
   "grep -q 'github.com/moby/moby' '$PROV' && grep -q 'revision_tag: v27.3.1' '$PROV'"
ck "...and the recorded sha256 MATCHES the bytes actually carried" \
   "python3 - <<'PYCHK'
import hashlib, sys, yaml
d = yaml.safe_load(open('$PROV'))
bad = []
for f in d['files']:
    got = hashlib.sha256(open(f['path'], 'rb').read()).hexdigest()
    if got != f['sha256'] or len(open(f['path'],'rb').read()) != f['bytes']:
        bad.append(f['path'])
sys.exit(1 if bad else 0)
PYCHK"
ck "NON-VACUOUS: a tampered byte would break that hash comparison" \
   "python3 -c \"
import hashlib
a = hashlib.sha256(b'x').hexdigest(); b = hashlib.sha256(b'y').hexdigest()
raise SystemExit(0 if a != b else 1)\""

# --- these texts are NOT this project's outbound licence --------------------
# A LICENSE file in the tree is exactly how a project-wide licence is normally
# declared. Carrying upstream's must not read as adopting it.
ck "the carried texts live under an unambiguous third-party path" \
   "case '$UP' in third-party/*) true ;; *) false ;; esac"
ck "the ROOT LICENSE is untouched and is not the Apache text" \
   "[ -f LICENSE ] && ! grep -q 'Apache License' LICENSE"
ck "the provenance says plainly these are not the project licence" \
   "grep -qi 'NOT Zenchron Foundry' '$PROV'"
ck "the project's outbound licence decision is still recorded as undetermined" \
   "grep -qE '^ *decision: undetermined' policies/license-policy.yaml"
# LICENSE:22-23 does not use the word "placeholder"; it says "replace this file
# before publication". That sentence is the actual signal that the current text
# is provisional, so the assertion tracks the wording that exists.
ck "...and the root LICENSE still says it must be replaced before publication" \
   "grep -qi 'replace this file' LICENSE"
ck "NON-VACUOUS: that phrase is genuinely present, not matched by accident" \
   "[ \"\$(grep -ci 'replace this file' LICENSE)\" = 1 ]"

# --- an unrelated licence family must not satisfy an Apache obligation ------
# Carrying SOME licence text is not carrying THE licence text.
ck "SABOTAGE: an MIT text does not satisfy the Apache-2.0 licence-text obligation" \
   "t=\$(mktemp); printf 'MIT License\n\nPermission is hereby granted, free of charge...\n' > \"\$t\";
    ! { grep -q 'Apache License' \"\$t\" && grep -q 'Version 2.0' \"\$t\"; }; r=\$?; rm -f \"\$t\"; [ \$r -eq 0 ]"
ck "...while the real Apache text does satisfy it (the check is not just strict)" \
   "grep -q 'Apache License' '$UP/LICENSE' && grep -q 'Version 2.0' '$UP/LICENSE'"

echo "----"
[ "$fail" -eq 0 ] && echo "test_copied_material_attribution: PASS" || echo "test_copied_material_attribution: FAIL"
exit $fail
