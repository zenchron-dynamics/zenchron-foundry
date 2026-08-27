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

# Files known to be copied or derived from an upstream project, and where their
# attribution lives. Adding a copied file without an entry here is the failure
# this test exists to catch.
declare -a COPIED=(
  "security/seccomp/zenchron-default.json|security/seccomp/NOTICE"
  "security/apparmor/zenchron-container|security/apparmor/zenchron-container"
)

for _pair in "${COPIED[@]}"; do
  _f="${_pair%%|*}"; _n="${_pair##*|}"
  ck "copied material exists: $_f" "[ -f '$_f' ]"
  ck "...its attribution exists: $_n" "[ -f '$_n' ]"
  ck "...naming the upstream project" "grep -qiE 'moby|docker' '$_n'"
  ck "...and the licence it is under" "grep -qiE 'apache|licen[sc]e' '$_n'"
  ck "...and a copyright line" "grep -qi 'copyright' '$_n'"
done

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

echo "----"
[ "$fail" -eq 0 ] && echo "test_copied_material_attribution: PASS" || echo "test_copied_material_attribution: FAIL"
exit $fail
