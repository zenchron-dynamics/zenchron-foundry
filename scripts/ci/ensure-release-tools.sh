#!/usr/bin/env bash
# =============================================================================
# scripts/ci/ensure-release-tools.sh
# -----------------------------------------------------------------------------
# Make the release gates self-provisioning: guarantee `gh` and `jq` are on PATH
# before scripts/check-release-environments.sh (and the rest of a release job)
# run. Self-hosted runners are not guaranteed to ship them, and the env-check
# fails CLOSED without them — so a missing tool would block a release for an
# infra reason. This installs the MISSING tool only, from a PINNED release,
# verified by sha256, to /usr/local/bin. Idempotent: a runner (or a
# GitHub-hosted image) that already has both is a no-op.
#
# Supply-chain: versions + checksums are pinned here, mirroring the repo's
# pin-everything policy. A download whose sha256 does not match is a hard
# failure — we never install an unverified binary into a security gate.
#
#   ensure-release-tools.sh              # ensure gh + jq (install if missing)
#   ensure-release-tools.sh --self-test  # offline checks of the pure logic
# =============================================================================
set -euo pipefail

GH_VER=2.63.2
JQ_VER=1.7.1
YQ_VER=4.44.6
BIN=/usr/local/bin

# sha256 by "<tool>-<arch>" (from the upstream signed checksum manifests).
sha_for() {
  case "$1" in
    gh-amd64) echo 912fdb1ca29cb005fb746fc5d2b787a289078923a29d0f9ec19a0b00272ded00 ;;
    gh-arm64) echo 0f31e2a8549c64b5c1679f0b99ce5e0dac7c91da9e86f6246adb8805b0f0b4bb ;;
    jq-amd64) echo 5942c9b0934e510ee61eb3e30273f1b3fe2590df93933a93d7c58b81d19c8ff5 ;;
    jq-arm64) echo 4dd2d8a0661df0b22f1bb9a1f9830f06b6f3b8f7d91211a1ef5d7c4f06a8b4a5 ;;
    yq-amd64) echo 0c2b24e645b57d8e7c0566d18643a6d4f5580feeea3878127354a46f2a1e4598 ;;
    yq-arm64) echo 9477ac3cc447b6c083986129e35af8122eb2b938fe55c9c3e40436fb966e5813 ;;
    *) return 1 ;;
  esac
}

arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) echo "ensure-release-tools: unsupported arch $(uname -m)" >&2; return 1 ;;
  esac
}

verify() { # <file> <tool-arch-key>
  local want got
  want="$(sha_for "$2")" || { echo "ensure-release-tools: no pinned checksum for $2" >&2; return 1; }
  got="$(sha256sum "$1" | awk '{print $1}')"
  [ "$got" = "$want" ] || { echo "ensure-release-tools: checksum mismatch for $2: got $got want $want" >&2; return 1; }
}

# Temp dir is created lazily (only when something must be downloaded) and torn
# down by a single EXIT trap — a no-op run never makes one.
TMP=""
cleanup() { if [ -n "$TMP" ]; then rm -rf "$TMP"; fi; }
need_tmp() { [ -n "$TMP" ] || TMP="$(mktemp -d)"; }

install_jq() {
  local a="$1"
  need_tmp
  echo "ensure-release-tools: installing jq $JQ_VER ($a)"
  curl -fsSL "https://github.com/jqlang/jq/releases/download/jq-${JQ_VER}/jq-linux-${a}" -o "$TMP/jq"
  verify "$TMP/jq" "jq-${a}"
  install -m 0755 "$TMP/jq" "$BIN/jq"
}

install_gh() {
  local a="$1"
  need_tmp
  echo "ensure-release-tools: installing gh $GH_VER ($a)"
  curl -fsSL "https://github.com/cli/cli/releases/download/v${GH_VER}/gh_${GH_VER}_linux_${a}.tar.gz" -o "$TMP/gh.tgz"
  verify "$TMP/gh.tgz" "gh-${a}"
  tar -xzf "$TMP/gh.tgz" -C "$TMP"
  install -m 0755 "$TMP/gh_${GH_VER}_linux_${a}/bin/gh" "$BIN/gh"
}

# yq is special: the runner ships a SNAP yq that is apparmor-confined and cannot
# read repo files under /opt/actions-runner (the identity/policy scripts then get
# an empty value and fail closed). `command -v yq` finds that snap, so we cannot
# skip on presence — we FORCE our pinned mikefarah yq into /usr/local/bin (ahead
# of /snap/bin on PATH). Skip only if OUR binary is already there with the right
# checksum.
ensure_yq() {
  local a="$1"
  if [ -x "$BIN/yq" ] && [ "$(sha256sum "$BIN/yq" | awk '{print $1}')" = "$(sha_for "yq-$a")" ]; then
    return 0
  fi
  need_tmp
  echo "ensure-release-tools: installing yq $YQ_VER ($a) -> $BIN (shadowing any snap yq)"
  curl -fsSL "https://github.com/mikefarah/yq/releases/download/v${YQ_VER}/yq_linux_${a}" -o "$TMP/yq"
  verify "$TMP/yq" "yq-${a}"
  install -m 0755 "$TMP/yq" "$BIN/yq"
}

ensure() {
  local a; a="$(arch)"
  trap cleanup EXIT
  command -v jq >/dev/null 2>&1 || install_jq "$a"
  command -v gh >/dev/null 2>&1 || install_gh "$a"
  ensure_yq "$a"
  command -v jq >/dev/null 2>&1 || { echo "ensure-release-tools: jq still missing" >&2; return 1; }
  command -v gh >/dev/null 2>&1 || { echo "ensure-release-tools: gh still missing" >&2; return 1; }
  [ -x "$BIN/yq" ] || { echo "ensure-release-tools: yq still missing" >&2; return 1; }
  echo "ensure-release-tools: OK (gh=$(command -v gh), jq=$(command -v jq), yq=$BIN/yq)"
}

self_test() {
  local ok=0 bad=0
  ck() { if eval "$2" >/dev/null 2>&1; then echo "  ok   $1"; ok=$((ok+1)); else echo "  FAIL $1"; bad=$((bad+1)); fi; }
  ck "sha_for gh-amd64 is 64-hex"  '[ "$(sha_for gh-amd64 | tr -d "\n" | wc -c)" -eq 64 ]'
  ck "sha_for jq-arm64 is 64-hex"  '[ "$(sha_for jq-arm64 | tr -d "\n" | wc -c)" -eq 64 ]'
  ck "sha_for yq-amd64 is 64-hex"  '[ "$(sha_for yq-amd64 | tr -d "\n" | wc -c)" -eq 64 ]'
  ck "sha_for rejects unknown key" '! sha_for bogus-key'
  ck "arch maps this host"         'arch'
  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

main() {
  if [ "${1:-}" = "--self-test" ]; then self_test; return; fi
  ensure
}
main "$@"
