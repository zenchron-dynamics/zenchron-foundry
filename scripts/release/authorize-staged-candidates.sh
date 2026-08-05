#!/usr/bin/env bash
# =============================================================================
# scripts/release/authorize-staged-candidates.sh
# -----------------------------------------------------------------------------
# The post-build authorization gate. Reads the per-child evidence produced by
# stage-and-authorize.yml and decides whether those EXACT staged platform child
# manifests may become inputs to an immutable release-candidate manifest.
#
# WHY THIS EXISTS AFTER THE BUILD. The previous gate ran in preflight, before
# anything was built, so it could not see the child digests or the vulnerability
# database the scan actually used. It therefore refused every publish outright —
# the honest interim state, but not a control. Authorization has to happen where
# the facts exist: after the children are pushed and evaluated, before anything
# is exposed.
#
# WHAT IT AUTHORIZES, EXACTLY. `authorization_scope` has one legal value,
# `immutable-rc-manifest-input`, and `public_exposure_authorized` is always
# false. A generic {"authorized": true} would invite a later consumer to read
# whatever authorization it needs into a record that never proved it. This
# record proves one thing: these digests, from this run, from this revision,
# judged against this database snapshot, are eligible as RC manifest inputs.
# Public exposure is decided elsewhere, by a protected path.
#
# EVERY EXPECTATION IS MANDATORY. The caller supplies the facts this run is
# claimed to be about, and the evidence is checked against them. Making any of
# them optional would be fail-open in the usual way: the binding disappears
# exactly when nobody wires it. Omitting one REFUSES.
#
#   EXPECTED_REPOSITORY        owner/repo
#   EXPECTED_REVISION          40-hex source revision
#   EXPECTED_RUN_ID            workflow run id
#   EXPECTED_RUN_ATTEMPT       workflow run attempt
#   EXPECTED_PLATFORMS         comma-separated, e.g. linux/amd64
#   EXPECTED_STAGING_PACKAGE   ghcr.io/<org>/<package>
#   EXPECTED_TRIVY_DB          canonical frozen database snapshot identity
#   WORKFLOW_REF               producing workflow reference
#   GENERATED_AT               RFC3339 UTC
#
# Usage:
#   authorize-staged-candidates.sh <child-evidence-dir> <output.json>
#   authorize-staged-candidates.sh --self-test
#
# A FAIL verdict is still WRITTEN before exiting non-zero. A refused
# authorization is exactly when the record matters, and a gate that fails
# without saying why forces the next person to guess.
# =============================================================================
set -euo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$_d/../lib/common.sh"

# Architectures this repository has reconciliation evidence for. PR A is
# architecture-generic, but it authorizes only what has actually been evidenced:
# the exception ledger records the architectures each acceptance was judged
# against, and arm64 has no such evidence yet (#139).
#
# The check is on the REQUESTED MATRIX, not per child. Staging an arm64 child
# and marking it unauthorized inside an otherwise passing record would produce a
# PASS that a careless consumer reads as covering everything present.
AUTHORIZED_PLATFORMS="${AUTHORIZED_PLATFORMS:-linux/amd64}"

SCOPE="immutable-rc-manifest-input"

# The ONE workflow identity allowed to produce an authorization record. Copying
# whatever the caller happened to be dispatched as would let a branch copy of the
# workflow emit a record that reads as authoritative — and workflow_dispatch can
# select any ref. This is a guard against accidental branch dispatch; it is NOT
# proof, because a record cannot vouch for itself. A consumer must independently
# verify the run through the GitHub API.
CANONICAL_WORKFLOW_REF="${CANONICAL_WORKFLOW_REF:-zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/master}"

# Media types that identify a single platform image. An INDEX must be refused:
# it can still be pulled with --platform, inspected and scanned, so every
# downstream check passes while the record describes the wrong object.
IMAGE_MEDIA_TYPES="application/vnd.oci.image.manifest.v1+json application/vnd.docker.distribution.manifest.v2+json"

# Deterministic checksum of an evidence directory. Must match the algorithm the
# staging job uses, or every child would be refused.
evidence_checksum() { # <dir>
  find "$1" -type f | LC_ALL=C sort | xargs shasum -a 256 | shasum -a 256 | cut -d' ' -f1
}

# ---------------------------------------------------------------------------
# Evaluation. Collects EVERY refusal rather than exiting on the first, so one
# run tells the operator everything that is wrong.
# ---------------------------------------------------------------------------
authorize() { # authorize <evidence-dir> <out.json>
  local dir="${1:?usage: authorize-staged-candidates.sh <child-evidence-dir> <output.json>}"
  local out="${2:?usage: authorize-staged-candidates.sh <child-evidence-dir> <output.json>}"
  local refusals=() children='[]'

  command -v jq >/dev/null || die "jq required"

  # --- mandatory expectations ---------------------------------------------
  local v
  for v in EXPECTED_REPOSITORY EXPECTED_REVISION EXPECTED_RUN_ID \
           EXPECTED_RUN_ATTEMPT EXPECTED_PLATFORMS EXPECTED_STAGING_PACKAGE \
           EXPECTED_TRIVY_DB WORKFLOW_REF GENERATED_AT BUILD_CREATED \
           EVIDENCE_ROOT; do
    [ -n "${!v:-}" ] || die "$v is required (every expectation is mandatory)"
  done
  is_hex40 "$EXPECTED_REVISION" || die "EXPECTED_REVISION is not 40-hex"
  case "$EXPECTED_RUN_ID"      in ''|*[!0-9]*) die "EXPECTED_RUN_ID must be numeric" ;; esac
  case "$EXPECTED_RUN_ATTEMPT" in ''|*[!0-9]*) die "EXPECTED_RUN_ATTEMPT must be numeric" ;; esac

  [ -d "$dir" ] || die "evidence directory not found: $dir"
  [ -d "$EVIDENCE_ROOT" ] || die "EVIDENCE_ROOT not found: $EVIDENCE_ROOT"

  # Workflow identity: pinned, not merely recorded.
  [ "$WORKFLOW_REF" = "$CANONICAL_WORKFLOW_REF" ] \
    || refusals+=("workflow_ref '$WORKFLOW_REF' is not the canonical producer '$CANONICAL_WORKFLOW_REF'")

  # --- architecture policy, on the requested matrix ------------------------
  local plat
  for plat in ${EXPECTED_PLATFORMS//,/ }; do
    case " $AUTHORIZED_PLATFORMS " in
      *" $plat "*) : ;;
      *) refusals+=("unsupported architecture '$plat': no reconciliation evidence exists for it (#139); the whole matrix is refused, not just this platform") ;;
    esac
  done

  # --- expected matrix -----------------------------------------------------
  local n_images n_plats expected_children
  n_images="$(matrix_image_labels | wc -l | tr -d ' ')"
  n_plats="$(printf '%s' "$EXPECTED_PLATFORMS" | tr ',' '\n' | grep -c .)"
  expected_children=$(( n_images * n_plats ))

  # --- collect children ----------------------------------------------------
  # Empty discovery is a refusal, never an empty PASS.
  local files=() f
  while IFS= read -r f; do files+=("$f"); done < <(find "$dir" -name '*.json' -type f | sort)
  [ "${#files[@]}" -gt 0 ] || refusals+=("no child evidence found in '$dir' (empty discovery is never success)")

  local seen_keys=() seen_dbs=() key
  for f in "${files[@]:-}"; do
    [ -n "$f" ] || continue
    local c
    if ! c="$(jq -c . "$f" 2>/dev/null)"; then
      refusals+=("$(basename "$f"): not valid JSON"); continue
    fi

    local label platform ref mdig mtype tdig vis carch db rev rid ratt repo smoke scan recon meta esum
    label="$(jq -r '.image_label      // ""' <<<"$c")"
    platform="$(jq -r '.platform        // ""' <<<"$c")"
    ref="$(jq -r '.digest_reference     // ""' <<<"$c")"
    mdig="$(jq -r '.manifest_digest     // ""' <<<"$c")"
    mtype="$(jq -r '.manifest_media_type // ""' <<<"$c")"
    tdig="$(jq -r '.tag_resolved_digest // ""' <<<"$c")"
    vis="$(jq -r '.visibility           // ""' <<<"$c")"
    carch="$(jq -r '.config_architecture// ""' <<<"$c")"
    db="$(jq -r '.trivy_db_identity     // ""' <<<"$c")"
    rev="$(jq -r '.source_revision      // ""' <<<"$c")"
    rid="$(jq -r '.workflow_run_id      // ""' <<<"$c")"
    ratt="$(jq -r '.workflow_run_attempt// ""' <<<"$c")"
    repo="$(jq -r '.repository          // ""' <<<"$c")"
    smoke="$(jq -r '.smoke_test         // ""' <<<"$c")"
    scan="$(jq -r '.scan                // ""' <<<"$c")"
    recon="$(jq -r '.reconciliation     // ""' <<<"$c")"
    meta="$(jq -r '.metadata_contract   // ""' <<<"$c")"
    esum="$(jq -r '.evidence_sha256     // ""' <<<"$c")"

    local id="${label:-<unlabelled>}@${platform:-<no-platform>}"

    # identity + duplicates
    if [ -z "$label" ] || [ -z "$platform" ]; then
      refusals+=("$(basename "$f"): missing image_label or platform"); continue
    fi
    key="${label}|${platform}"
    case " ${seen_keys[*]:-} " in
      *" $key "*) refusals+=("$id: duplicate entry — one child per image/platform") ;;
      *) seen_keys+=("$key") ;;
    esac

    # provenance: this run, this attempt, this repo, this revision
    [ "$repo" = "$EXPECTED_REPOSITORY" ] || refusals+=("$id: repository '$repo' != expected '$EXPECTED_REPOSITORY'")
    [ "$rev"  = "$EXPECTED_REVISION" ]   || refusals+=("$id: source_revision '$rev' != expected '$EXPECTED_REVISION'")
    [ "$rid"  = "$EXPECTED_RUN_ID" ]     || refusals+=("$id: workflow_run_id '$rid' != expected '$EXPECTED_RUN_ID'")
    [ "$ratt" = "$EXPECTED_RUN_ATTEMPT" ] || refusals+=("$id: workflow_run_attempt '$ratt' != expected '$EXPECTED_RUN_ATTEMPT'")

    # references must be immutable and must name the staging package
    case "$ref" in
      "${EXPECTED_STAGING_PACKAGE}@sha256:"*) : ;;
      *"@sha256:"*) refusals+=("$id: digest_reference '$ref' is not in the staging package '$EXPECTED_STAGING_PACKAGE'") ;;
      *) refusals+=("$id: digest_reference '$ref' is mutable or malformed — a by-digest reference is required") ;;
    esac
    is_digest "$mdig" || refusals+=("$id: manifest_digest '$mdig' is not sha256:<64-hex>")
    is_digest "$tdig" || refusals+=("$id: tag_resolved_digest '$tdig' is not sha256:<64-hex>")
    if is_digest "$mdig" && is_digest "$tdig" && [ "$mdig" != "$tdig" ]; then
      refusals+=("$id: staging tag resolves to '$tdig' but the manifest digest is '$mdig' — the tag does not serve what was evaluated")
    fi
    case "$ref" in *"@${mdig}") : ;; *) refusals+=("$id: digest_reference does not end in the manifest digest") ;; esac

    # the digest must name a platform image, never an index
    case " $IMAGE_MEDIA_TYPES " in
      *" $mtype "*) : ;;
      *index*|*"manifest.list"*) refusals+=("$id: manifest_media_type '$mtype' is an INDEX; the record must describe a platform child") ;;
      *) refusals+=("$id: manifest_media_type '${mtype:-<missing>}' is not an image manifest media type") ;;
    esac

    # quarantine must still be private
    [ "$vis" = private ] || refusals+=("$id: staging visibility is '$vis', not private")

    # the child must be the architecture it claims
    case "${platform#linux/}" in
      "$carch") : ;;
      *) refusals+=("$id: config architecture '$carch' does not match platform '$platform'") ;;
    esac

    # one frozen database for the whole record
    [ -n "$db" ] || refusals+=("$id: trivy_db_identity is empty")
    [ "$db" = "$EXPECTED_TRIVY_DB" ] || refusals+=("$id: trivy_db_identity '$db' != the run's frozen snapshot '$EXPECTED_TRIVY_DB'")
    case " ${seen_dbs[*]:-} " in *" $db "*) : ;; *) [ -n "$db" ] && seen_dbs+=("$db") ;; esac

    # per-child gates
    [ "$smoke" = PASS ] || refusals+=("$id: smoke_test is '$smoke'")
    [ "$scan"  = PASS ] || refusals+=("$id: scan is '$scan'")
    [ "$recon" = PASS ] || refusals+=("$id: reconciliation is '$recon' — an ungoverned vulnerability finding")
    [ "$meta"  = PASS ] || refusals+=("$id: metadata_contract is '$meta' (#126)")

    # The checksum is RECOMPUTED, not merely shape-checked. A well-formed but
    # invented 64-hex value used to pass, which made the binding decorative.
    if ! printf '%s' "$esum" | grep -Eq '^[0-9a-f]{64}$'; then
      refusals+=("$id: evidence_sha256 is missing or malformed")
    else
      local slug edir actual
      slug="${label//\//-}"
      edir="${EVIDENCE_ROOT}/${slug}-evidence"
      if [ ! -d "$edir" ]; then
        refusals+=("$id: no evidence directory at '${slug}-evidence' to check the checksum against")
      else
        actual="$(evidence_checksum "$edir")"
        [ "$actual" = "$esum" ] \
          || refusals+=("$id: evidence_sha256 '$esum' does not match the evidence directory (recomputed '$actual')")
      fi
    fi

    children="$(jq -c --argjson c "$c" '. + [$c]' <<<"$children")"
  done

  # more than one database identity across children
  if [ "${#seen_dbs[@]}" -gt 1 ]; then
    refusals+=("children were evaluated against ${#seen_dbs[@]} different vulnerability database snapshots; one record cannot mix knowledge states")
  fi

  # --- completeness, against the DECLARED matrix ---------------------------
  local have="${#seen_keys[@]}"
  if [ "$have" -ne "$expected_children" ]; then
    refusals+=("expected $expected_children children ($n_images images x $n_plats platforms), found $have")
  fi
  local want_label want_plat
  while IFS= read -r want_label; do
    for want_plat in ${EXPECTED_PLATFORMS//,/ }; do
      case " ${seen_keys[*]:-} " in
        *" ${want_label}|${want_plat} "*) : ;;
        *) refusals+=("missing expected child: ${want_label} on ${want_plat}") ;;
      esac
    done
  done < <(matrix_image_labels)
  # unexpected extras
  for key in "${seen_keys[@]:-}"; do
    [ -n "$key" ] || continue
    local kl="${key%|*}" kp="${key#*|}"
    if ! matrix_image_labels | grep -qxF "$kl"; then
      refusals+=("unexpected child '$kl' is not in the image matrix")
    elif ! printf '%s' "$EXPECTED_PLATFORMS" | tr ',' '\n' | grep -qxF "$kp"; then
      refusals+=("unexpected child '$kl' on unrequested platform '$kp'")
    fi
  done

  # --- verdict -------------------------------------------------------------
  local verdict=PASS
  [ "${#refusals[@]}" -eq 0 ] || verdict=FAIL

  local refusals_json='[]'
  if [ "${#refusals[@]}" -gt 0 ]; then
    refusals_json="$(printf '%s\n' "${refusals[@]}" | jq -R . | jq -sc .)"
  fi

  mkdir -p "$(dirname "$out")"
  jq -n \
    --arg repo "$EXPECTED_REPOSITORY" --arg rev "$EXPECTED_REVISION" \
    --argjson rid "$EXPECTED_RUN_ID" --argjson ratt "$EXPECTED_RUN_ATTEMPT" \
    --arg wref "$WORKFLOW_REF" --arg gen "$GENERATED_AT" \
    --arg bcreated "$BUILD_CREATED" \
    --arg db "$EXPECTED_TRIVY_DB" --arg pkg "$EXPECTED_STAGING_PACKAGE" \
    --argjson imgs "$n_images" \
    --argjson plats "$(printf '%s' "$EXPECTED_PLATFORMS" | tr ',' '\n' | jq -R . | jq -sc .)" \
    --argjson exp "$expected_children" \
    --argjson children "$children" --arg scope "$SCOPE" \
    --arg verdict "$verdict" --argjson refusals "$refusals_json" '
    {schema_version: 1, repository: $repo, source_revision: $rev,
     workflow_run_id: $rid, workflow_run_attempt: $ratt, workflow_ref: $wref,
     generated_at: $gen, build_created: $bcreated,
     trivy_db_snapshot: {identity: $db, frozen: true},
     staging_package: $pkg,
     expected_matrix: {images: $imgs, platforms: $plats, expected_children: $exp},
     children: $children,
     authorization_scope: $scope,
     public_exposure_authorized: false,
     verdict: $verdict}
    | if $verdict == "FAIL" then . + {refusals: $refusals} else . end' > "$out"

  if [ "$verdict" = FAIL ]; then
    printf 'REFUSED (%d):\n' "${#refusals[@]}" >&2
    printf '  - %s\n' "${refusals[@]}" >&2
    return 1
  fi
  log "AUTHORIZED: $have/$expected_children children eligible as $SCOPE (public exposure NOT authorized)"
}

# ---------------------------------------------------------------------------
# self-test
# ---------------------------------------------------------------------------
_asc_self_test() {
  local ok=0 bad=0 tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local REV="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  local DIG SUM
  DIG="sha256:$(printf 'b%.0s' {1..64})"
  SUM="$(printf 'c%.0s' {1..64})"
  local PKG="ghcr.io/zenchron-dynamics/foundry-staging"

  export EXPECTED_REPOSITORY="zenchron-dynamics/zenchron-foundry" \
         EXPECTED_REVISION="$REV" EXPECTED_RUN_ID=1 EXPECTED_RUN_ATTEMPT=1 \
         EXPECTED_PLATFORMS="linux/amd64" EXPECTED_STAGING_PACKAGE="$PKG" \
         EXPECTED_TRIVY_DB="db@2026-08-05" BUILD_CREATED="2026-08-06T00:00:00Z" \
         WORKFLOW_REF="$CANONICAL_WORKFLOW_REF" GENERATED_AT="2026-08-05T00:00:00Z"

  # writes a full evidence set; $1 = dir, $2 = jq mutation applied to ONE child
  _mk() { # _mk <dir> [label-to-mutate] [jq-filter]
    local d="$1" target="${2:-}" filt="${3:-.}" lbl i=0
    mkdir -p "$d"
    export EVIDENCE_ROOT="$d"
    while IFS= read -r lbl; do
      i=$((i+1))
      local base slug edir
      slug="${lbl//\//-}"; edir="$d/${slug}-evidence"
      mkdir -p "$edir"; printf 'evidence for %s\n' "$lbl" > "$edir/log.txt"
      SUM="$(evidence_checksum "$edir")"
      base="$(jq -nc --arg l "$lbl" --arg d "$DIG" --arg s "$SUM" --arg p "$PKG" \
                --arg rev "$REV" --arg repo "$EXPECTED_REPOSITORY" '{
        image_label:$l, platform:"linux/amd64",
        staging_tag:($l|gsub("/";"-"))+"-r1-a1-saaaaaaa-amd64",
        digest_reference:($p+"@"+$d), manifest_digest:$d, tag_resolved_digest:$d,
        visibility:"private", config_architecture:"amd64",
        manifest_media_type:"application/vnd.oci.image.manifest.v1+json",
        trivy_db_identity:"db@2026-08-05", source_revision:$rev,
        workflow_run_id:1, workflow_run_attempt:1, repository:$repo,
        smoke_test:"PASS", scan:"PASS", reconciliation:"PASS",
        metadata_contract:"PASS", evidence_sha256:$s}')"
      if [ -n "$target" ] && [ "$lbl" = "$target" ]; then
        base="$(jq -c "$filt" <<<"$base")"
      fi
      printf '%s' "$base" > "$d/child-$i.json"
    done < <(matrix_image_labels)
  }

  t() { # t <name> <expect pass|fail> <dir>
    local name="$1" expect="$2" d="$3"
    if ( authorize "$d" "$d/out.json" >/dev/null 2>&1 ); then
      [ "$expect" = pass ] && { echo "ok   - $name"; ok=$((ok+1)); return; }
    else
      [ "$expect" = fail ] && { echo "ok   - $name"; ok=$((ok+1)); return; }
    fi
    echo "FAIL - $name (expected $expect)"; bad=$((bad+1))
  }

  local d="$tmp/happy"; _mk "$d"; t "a complete, consistent matrix is authorized" pass "$d"
  [ "$(jq -r .verdict "$d/out.json")" = PASS ] \
    && { echo "ok   - ...verdict PASS"; ok=$((ok+1)); } || { echo "FAIL - ...verdict PASS"; bad=$((bad+1)); }
  [ "$(jq -r .authorization_scope "$d/out.json")" = "$SCOPE" ] \
    && { echo "ok   - ...scope is the single legal value"; ok=$((ok+1)); } || { echo "FAIL - scope"; bad=$((bad+1)); }
  [ "$(jq -r .public_exposure_authorized "$d/out.json")" = false ] \
    && { echo "ok   - ...public exposure NOT authorized"; ok=$((ok+1)); } || { echo "FAIL - exposure"; bad=$((bad+1)); }

  d="$tmp/missing"; _mk "$d"; rm -f "$d/child-1.json"
  t "a missing expected child refuses" fail "$d"

  d="$tmp/extra"; _mk "$d"
  jq -c '.image_label="not-an-image/prod"' "$d/child-1.json" > "$d/child-99.json"
  t "an unexpected extra child refuses" fail "$d"

  d="$tmp/dup"; _mk "$d"; cp "$d/child-1.json" "$d/child-dup.json"
  t "a duplicate image/platform refuses" fail "$d"

  d="$tmp/run"; _mk "$d" "nginx/prod" '.workflow_run_id=999'
  t "evidence from another run refuses" fail "$d"

  d="$tmp/att"; _mk "$d" "nginx/prod" '.workflow_run_attempt=2'
  t "evidence from another attempt refuses" fail "$d"

  d="$tmp/repo"; _mk "$d" "nginx/prod" '.repository="someone/else"'
  t "evidence from another repository refuses" fail "$d"

  d="$tmp/sha"; _mk "$d" "nginx/prod" '.source_revision="0000000000000000000000000000000000000000"'
  t "evidence from another source revision refuses" fail "$d"

  d="$tmp/mutable"; _mk "$d" "nginx/prod" '.digest_reference="ghcr.io/zenchron-dynamics/foundry-staging:sometag"'
  t "a mutable-only reference refuses" fail "$d"

  d="$tmp/otherpkg"; _mk "$d" "nginx/prod" '.digest_reference=("ghcr.io/zenchron-dynamics/php-fpm@"+.manifest_digest)'
  t "a reference outside the staging package refuses" fail "$d"

  d="$tmp/tagdig"; _mk "$d" "nginx/prod" '.tag_resolved_digest="sha256:'"$(printf 'd%.0s' {1..64})"'"'
  t "staging tag/digest disagreement refuses" fail "$d"

  d="$tmp/vis"; _mk "$d" "nginx/prod" '.visibility="public"'
  t "non-private staging visibility refuses" fail "$d"

  d="$tmp/arch"; _mk "$d" "nginx/prod" '.config_architecture="arm64"'
  t "digest architecture mismatch refuses" fail "$d"

  d="$tmp/db"; _mk "$d" "nginx/prod" '.trivy_db_identity="db@2026-01-01"'
  t "a different vulnerability database snapshot refuses" fail "$d"

  d="$tmp/smoke"; _mk "$d" "nginx/prod" '.smoke_test="FAIL"'
  t "a failed smoke test refuses" fail "$d"

  d="$tmp/recon"; _mk "$d" "nginx/prod" '.reconciliation="FAIL"'
  t "an unreconciled vulnerability finding refuses" fail "$d"

  d="$tmp/scan"; _mk "$d" "nginx/prod" '.scan="FAIL"'
  t "a failed scan refuses" fail "$d"

  d="$tmp/meta"; _mk "$d" "nginx/prod" '.metadata_contract="FAIL"'
  t "a metadata contract mismatch refuses (#126)" fail "$d"

  d="$tmp/sum"; _mk "$d" "nginx/prod" 'del(.evidence_sha256)'
  t "a missing evidence checksum refuses" fail "$d"

  d="$tmp/index"; _mk "$d" "nginx/prod" '.manifest_media_type="application/vnd.oci.image.index.v1+json"'
  t "an INDEX digest refuses (it is not a platform child)" fail "$d"

  d="$tmp/mlist"; _mk "$d" "nginx/prod" '.manifest_media_type="application/vnd.docker.distribution.manifest.list.v2+json"'
  t "a docker manifest list refuses" fail "$d"

  d="$tmp/nomtype"; _mk "$d" "nginx/prod" 'del(.manifest_media_type)'
  t "a missing manifest media type refuses" fail "$d"

  # THE case that made the checksum decorative: well-formed, plausible, wrong.
  d="$tmp/badsum"; _mk "$d" "nginx/prod" '.evidence_sha256="'"$(printf 'e%.0s' {1..64})"'"'
  t "a well-formed but INCORRECT evidence checksum refuses" fail "$d"

  d="$tmp/nodir"; _mk "$d"; rm -rf "$d/nginx-prod-evidence"
  t "a checksum with no evidence directory to check against refuses" fail "$d"

  d="$tmp/tampered"; _mk "$d"; printf 'tampered\n' >> "$d/nginx-prod-evidence/log.txt"
  t "evidence altered after the checksum was taken refuses" fail "$d"

  d="$tmp/wfref"; _mk "$d"
  ( export WORKFLOW_REF="zenchron-dynamics/zenchron-foundry/.github/workflows/stage-and-authorize.yml@refs/heads/some-branch"
    ! authorize "$d" "$d/out.json" >/dev/null 2>&1 ) \
    && { echo "ok   - a non-canonical workflow identity refuses"; ok=$((ok+1)); } \
    || { echo "FAIL - workflow identity"; bad=$((bad+1)); }

  d="$tmp/empty"; mkdir -p "$d"; export EVIDENCE_ROOT="$d"
  t "empty evidence discovery refuses, never an empty PASS" fail "$d"

  d="$tmp/badjson"; _mk "$d"; printf 'not json' > "$d/child-1.json"
  t "malformed evidence refuses" fail "$d"

  # architecture policy is on the REQUESTED MATRIX
  d="$tmp/arm"; _mk "$d"
  ( export EXPECTED_PLATFORMS="linux/amd64,linux/arm64"
    ! authorize "$d" "$d/out.json" >/dev/null 2>&1 ) \
    && { echo "ok   - an unevidenced architecture refuses the WHOLE matrix"; ok=$((ok+1)); } \
    || { echo "FAIL - arm64 matrix"; bad=$((bad+1)); }

  # a FAIL record is still written
  d="$tmp/writefail"; _mk "$d"; rm -f "$d/child-1.json"
  authorize "$d" "$d/out.json" >/dev/null 2>&1 || true
  if [ -s "$d/out.json" ] && [ "$(jq -r .verdict "$d/out.json")" = FAIL ] \
     && [ "$(jq '.refusals|length' "$d/out.json")" -gt 0 ]; then
    echo "ok   - a FAIL record is written, with its reasons"; ok=$((ok+1))
  else echo "FAIL - FAIL record"; bad=$((bad+1)); fi

  # mandatory expectations
  # `die` exits the subshell, so the status has to be captured by `if` — a `!`
  # in front of the call never runs.
  d="$tmp/mand"; _mk "$d"
  local mv
  for mv in EXPECTED_TRIVY_DB EXPECTED_REPOSITORY EXPECTED_REVISION \
            EXPECTED_STAGING_PACKAGE WORKFLOW_REF BUILD_CREATED EVIDENCE_ROOT; do
    if ( unset "$mv"; authorize "$d" "$d/out.json" ) >/dev/null 2>&1; then
      echo "FAIL - omitting $mv should refuse"; bad=$((bad+1))
    else
      echo "ok   - omitting $mv refuses"; ok=$((ok+1))
    fi
  done

  echo "self-test: $ok ok, $bad failed"
  [ "$bad" -eq 0 ]
}

case "${1:-}" in
  --self-test) _asc_self_test && echo "authorize-staged-candidates.sh: SELF-TEST OK" ;;
  "") echo "usage: authorize-staged-candidates.sh <child-evidence-dir> <output.json> | --self-test" >&2; exit 2 ;;
  *) authorize "$@" ;;
esac
