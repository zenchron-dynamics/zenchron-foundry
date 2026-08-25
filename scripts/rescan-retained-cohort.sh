#!/usr/bin/env bash
# =============================================================================
# scripts/rescan-retained-cohort.sh
# -----------------------------------------------------------------------------
# BUILDLESS rescan of an already-accepted production cohort.
#
# WHY THIS IS NOT A REBUILD.
#
# Re-deciding an exception's expiry needs fresh vulnerability data about the
# artifact that was actually accepted — not about a NEW artifact built today
# from the same Dockerfile. Those are different images: a rebuild picks up
# whatever the upstream base tag points at now, so a rebuild-and-scan answers
# "what would we ship if we built today", which is a different question from
# "is the accepted cohort still governed". This script therefore never builds.
# It reads the immutable child manifest digests out of an accepted acceptance
# evidence record and scans THOSE digests straight from the registry.
#
# WHY THE DATABASE IS FROZEN ONCE.
#
# Trivy refreshes its vulnerability database on a schedule. If each child were
# scanned against whatever database happened to be current at that moment, the
# cohort would be measured against a moving target and a per-child difference
# could not be attributed to the child rather than to the database. One
# database is downloaded, its identity is recorded, and every subsequent scan
# runs with --skip-db-update against that same frozen snapshot.
#
# WHAT EACH SCAN IS BOUND TO (all of it, or the result proves nothing):
#   immutable child digest | platform | source revision the child represents |
#   scanner image digest   | frozen database identity | ledger+policy digest |
#   evidence class
#
# Usage:
#   scripts/rescan-retained-cohort.sh --evidence <acceptance-evidence.json> \
#                                     --out <dir> [--limit N]
#   scripts/rescan-retained-cohort.sh --self-test
#
# Credentials: GHCR_USER / GHCR_TOKEN, or a `gh auth token` login.
# Exit: 0 when every child was scanned and reconciled; 1 on any failure. A
# child that cannot be scanned is a FAILURE, never an empty clean result.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# The scanner is pinned by digest. A floating scanner tag makes "same scanner"
# unverifiable, which is the same defect as a floating database.
SCANNER_IMAGE="${SCANNER_IMAGE:-aquasec/trivy:0.73.0@sha256:7cced7cae583819fc7806d4cbc0dbbc7cad18b99f7d3e235192e6da8c091045c}"

_log() { printf '%s\n' "$*"; }
_die() { printf 'REFUSE: %s\n' "$*" >&2; exit 1; }

# family/version from a child_key such as 'php-cli/8.3/linux/amd64'.
_family_of() { printf '%s' "${1%%/*}"; }
_version_of() { local r="${1#*/}"; printf '%s' "${r%%/*}"; }
# platform from the same key: the trailing 'linux/<arch>'.
_platform_of() {
    local k="$1" a b
    b="${k##*/}"; k="${k%/*}"; a="${k##*/}"
    printf '%s/%s' "$a" "$b"
}

# ---------------------------------------------------------------------------
# freeze_db <cache-dir> -> writes <cache-dir>/../db-identity.txt
# Downloads exactly one database and reports its identity. Everything after
# this runs --skip-db-update, so the snapshot cannot move mid-cohort.
# ---------------------------------------------------------------------------
freeze_db() {
    local cache="$1" ident
    mkdir -p "$cache"
    _log "==> acquiring ONE fresh vulnerability database (this is the only download)"
    docker run --rm -v "$cache:/root/.cache/trivy" "$SCANNER_IMAGE" \
        image --download-db-only >&2 || _die "vulnerability database download failed"
    [ -f "$cache/db/metadata.json" ] || _die "no db/metadata.json after download"
    ident="$(python3 - "$cache/db/metadata.json" <<'PY'
import json, sys
m = json.load(open(sys.argv[1]))
print("v%s+updated:%s+next:%s" % (m["Version"], m["UpdatedAt"], m["NextUpdate"]))
PY
)"
    printf '%s\n' "$ident"
}

scan_child() {
    local ref="$1" cache="$2" out="$3"
    docker run --rm \
        -e TRIVY_USERNAME -e TRIVY_PASSWORD \
        -v "$cache:/root/.cache/trivy" \
        -v "$(dirname "$out"):/work" \
        "$SCANNER_IMAGE" image \
            --skip-db-update --skip-java-db-update \
            --severity CRITICAL,HIGH \
            --exit-code 0 \
            --format json --output "/work/$(basename "$out")" \
            "$ref"
}

main() {
    local evidence="" out="" limit=0
    while [ $# -gt 0 ]; do
        case "$1" in
            --evidence) evidence="$2"; shift 2 ;;
            --out) out="$2"; shift 2 ;;
            --limit) limit="$2"; shift 2 ;;
            *) _die "unknown argument '$1'" ;;
        esac
    done
    [ -n "$evidence" ] || _die "--evidence <acceptance-evidence.json> is required"
    [ -n "$out" ] || _die "--out <dir> is required"
    [ -f "$evidence" ] || _die "no such evidence file: $evidence"

    mkdir -p "$out/scans" "$out/reconciliations"

    if [ -z "${TRIVY_PASSWORD:-}" ]; then
        TRIVY_USERNAME="${GHCR_USER:-$(gh api user --jq .login 2>/dev/null || true)}"
        TRIVY_PASSWORD="${GHCR_TOKEN:-$(gh auth token 2>/dev/null || true)}"
        export TRIVY_USERNAME TRIVY_PASSWORD
    fi
    [ -n "${TRIVY_PASSWORD:-}" ] || _die "no registry credential (set GHCR_TOKEN or run gh auth login)"

    local cache="$out/.trivy-cache" db_identity
    db_identity="$(freeze_db "$cache")"
    _log "==> frozen database identity: $db_identity"
    printf '%s\n' "$db_identity" > "$out/frozen-db-identity.txt"

    # Everything the refresh is bound to, captured BEFORE the first scan so a
    # mid-run policy edit cannot be silently folded into the result.
    local policy_sha ledger_sha source_rev
    ledger_sha="$(shasum -a 256 "$ROOT/policies/vulnerability-exceptions.yaml" | cut -d' ' -f1)"
    policy_sha="$(shasum -a 256 "$ROOT/policies/evidence-classes.yaml" | cut -d' ' -f1)"
    source_rev="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["source_revision"])' "$evidence")"

    local n=0 failed=0
    while IFS='|' read -r child_key digest ref platform; do
        [ -n "$child_key" ] || continue
        n=$((n + 1))
        if [ "$limit" -gt 0 ] && [ "$n" -gt "$limit" ]; then break; fi
        local slug fam ver scan rec
        slug="$(printf '%s' "$child_key" | tr '/' '_')"
        fam="$(_family_of "$child_key")"; ver="$(_version_of "$child_key")"
        scan="$out/scans/${slug}.trivy.json"
        rec="$out/reconciliations/${slug}.reconcile.json"
        _log "==> [$n] $child_key  $digest  ($platform)"
        if [ ! -s "$scan" ]; then
            scan_child "$ref" "$cache" "$scan" || { _log "SCAN FAILED: $child_key"; failed=1; continue; }
        else
            _log "    (scan already present, reusing)"
        fi
        # The repository's OWN gate decides which record governed which finding.
        # Nothing here re-implements the matching rules.
        TODAY="${TODAY:-$(date -u +%F)}" \
        bash "$ROOT/scripts/reconcile-vulnerabilities.sh" "$scan" "$fam" "$ver" \
            --arch "$platform" --json "$rec" >"$out/reconciliations/${slug}.log" 2>&1 || true
        [ -s "$rec" ] || { _log "RECONCILE PRODUCED NO REPORT: $child_key"; failed=1; continue; }
        python3 - "$rec" "$digest" "$ref" "$platform" "$source_rev" "$SCANNER_IMAGE" \
                 "$db_identity" "$ledger_sha" "$policy_sha" <<'PY'
import json, sys
p = sys.argv[1]
d = json.load(open(p))
d["binding"] = {
    "child_digest": sys.argv[2],
    "digest_reference": sys.argv[3],
    "platform": sys.argv[4],
    "source_revision": sys.argv[5],
    "scanner": sys.argv[6],
    "frozen_vulnerability_database": sys.argv[7],
    "exception_ledger_sha256": sys.argv[8],
    "evidence_class_policy_sha256": sys.argv[9],
    "evidence_class": "staged-candidate",
    "rescan_mode": "buildless-digest-rescan",
}
json.dump(d, open(p, "w"), indent=2, default=str)
open(p, "a").write("\n")
PY
    done < <(python3 - "$evidence" <<'PY'
import json, sys
for c in json.load(open(sys.argv[1]))["children"]:
    print("%s|%s|%s|%s" % (c["child_key"], c["manifest_digest"],
                           c["digest_reference"], c["platform"]))
PY
)
    _log "==> rescanned $n child(ren); failures: $failed"
    return "$failed"
}

self_test() {
    local rc=0
    _t() {
        if eval "$2" >/dev/null 2>&1; then printf 'ok   %s\n' "$1"
        else printf 'FAIL %s\n' "$1"; rc=1; fi
    }
    _t "family of a versioned child key"   '[ "$(_family_of php-cli/8.3/linux/amd64)" = php-cli ]'
    _t "version of a versioned child key"  '[ "$(_version_of php-cli/8.3/linux/amd64)" = 8.3 ]'
    _t "family of a prod child key"        '[ "$(_family_of caddy/prod/linux/arm64)" = caddy ]'
    _t "version of a prod child key"       '[ "$(_version_of caddy/prod/linux/arm64)" = prod ]'
    _t "platform of a child key"           '[ "$(_platform_of php-fpm/8.4/linux/arm64)" = linux/arm64 ]'
    _t "platform is not the family"        '[ "$(_platform_of caddy/prod/linux/amd64)" = linux/amd64 ]'
    _t "scanner is digest-pinned"          'case "$SCANNER_IMAGE" in *@sha256:*) true ;; *) false ;; esac'
    # Each refusal runs in a SUBSHELL: _die exits, and an exit inside `eval`
    # would tear down the self-test itself rather than being observed as a
    # refusal — the assertion would then be untestable, not passing.
    _t "missing --evidence is refused"     '! ( main --out /tmp )'
    _t "missing --out is refused"          '! ( main --evidence /dev/null )'
    _t "unknown argument is refused"       '! ( main --nope )'
    _t "a nonexistent evidence file fails" '! ( main --evidence /nonexistent.json --out /tmp )'
    if [ "$rc" -eq 0 ]; then printf 'rescan-retained-cohort.sh: SELF-TEST OK (11 assertions)\n'
    else printf 'rescan-retained-cohort.sh: SELF-TEST FAILED\n'; fi
    return "$rc"
}

if [ "${1:-}" = "--self-test" ]; then self_test; else main "$@"; fi
