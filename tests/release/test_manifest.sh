#!/usr/bin/env bash
# Phase C — RC manifest lifecycle + verifier identity policy.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
fail=0
NIMG="$(bash -c '. scripts/lib/common.sh; matrix_image_labels' | grep -c .)"
NCHILD=$(( NIMG * 2 ))
ck() { if eval "$2"; then echo "ok   - $1"; else echo "FAIL - $1"; fail=1; fi; }

ck "manifest validator self-test"  'bash scripts/validate-release-manifest.sh --self-test >/dev/null'
ck "cosign-identity self-test"      'bash scripts/lib/cosign-identity.sh --self-test >/dev/null'
ck "identity verifier self-test"    'bash scripts/verify-image-release-identity.sh --self-test >/dev/null'
ck "manifest verifier self-test"    'bash scripts/verify-release-manifest.sh --self-test >/dev/null'
ck "manifest generator self-test"   'bash scripts/generate-release-manifest.sh --self-test >/dev/null'

# End-to-end offline: generate -> sign(LOCAL) -> verify(LOCAL).
tmpd="$(mktemp -d)"; mkdir -p "$tmpd/bin"
printf '#!/usr/bin/env bash\necho "sha256:$(printf "%%s" "$1" | shasum -a256 | cut -c1-64)"\n' > "$tmpd/bin/mockdig"
printf '#!/usr/bin/env bash\necho "linux/amd64,linux/arm64"\n' > "$tmpd/bin/mockplat"
chmod +x "$tmpd/bin"/*
R=7b4985a1234567890abcdef1234567890abcdef1
PATH="$tmpd/bin:$PATH" RESOLVE_DIGEST_FN=mockdig RESOLVE_PLATFORMS_FN=mockplat \
  bash scripts/generate-release-manifest.sh v2026.07.03 --rc rc1 --revision "$R" --created-at 2026-07-03T12:00:00Z > "$tmpd/m.yaml" 2>/dev/null

ck "generated manifest has $NIMG images" 'test "$(yq -r ".images|keys|length" "$tmpd/m.yaml")" = "$NIMG"'
ck "generated manifest validates"     'bash scripts/validate-release-manifest.sh "$tmpd/m.yaml" >/dev/null'
ck "sign (LOCAL) writes checksum"     'LOCAL=1 bash scripts/sign-release-manifest.sh "$tmpd/m.yaml" >/dev/null 2>&1 && test -f "$tmpd/m.yaml.sha256"'
ck "verify (LOCAL) passes"            'LOCAL=1 bash scripts/verify-release-manifest.sh "$tmpd/m.yaml" >/dev/null 2>&1'
# tamper -> checksum mismatch caught
printf '\n# tampered\n' >> "$tmpd/m.yaml"
ck "verify detects checksum tamper"   '! LOCAL=1 bash scripts/verify-release-manifest.sh "$tmpd/m.yaml" >/dev/null 2>&1'
rm -rf "$tmpd"

echo "----"; [ "$fail" -eq 0 ] && echo "test_manifest: PASS" || echo "test_manifest: FAIL"
exit $fail
