#!/usr/bin/env bash
# =============================================================================
# scripts/experimental/experimental-run.sh
# -----------------------------------------------------------------------------
# Executes the capabilities of an experimental cohort against the children that
# scripts/experimental/experimental-plan.sh enumerates, and writes classed
# evidence for each one.
#
# IT DOES NOT ENUMERATE. Every child, context, platform, required-extension set
# and evidence class is read from the plan. A second enumeration is the one
# change that could let this runner reach an image the plan refuses, so it
# cannot list images at all: given no plan, it does nothing.
#
# WHAT IT PRODUCES PER CHILD, and why each is a separate fact:
#
#   OCI-layout identity   the manifest digest of the built image, read out of a
#                         real OCI layout. A local tag is not an identity.
#   source revision       the Foundry commit whose contexts were built.
#   build-input digest    the build CONTEXT digest, from the plan. Two artifacts
#                         from the same revision but a different context are
#                         different artifacts.
#   upstream base digest  the digest the Dockerfile pins, recorded as the
#                         evidence record's `parent`. This is what makes the
#                         child traceable to the exact base bytes.
#   PHP / SAPI identity   from the running child, never from the tag.
#   extension inventory   the full loaded set, plus the cohort's required set.
#   OPcache provenance    base-builtin vs helper-installed, PLUS a runtime proof
#                         via opcache_get_status(). "Listed in php -m" and
#                         "actually caching" are different claims.
#   redis proof           the ext version AND a live Redis::class check.
#   package inventory     dpkg-query over the CHILD. THE 241-vs-47 FIELD.
#   purge proof           gcc / make / phpize absent, tested by execution.
#   SBOM                  syft, from the built child.
#   scan                  trivy, against the CHILD, under ONE frozen database.
#
# THE SCAN TARGET IS THE CHILD, ALWAYS. The upstream php:8.4 BASE reports 241
# CRITICAL/HIGH including 170 linux-libc-dev; the 8.4 CHILD reports 47 and none,
# because the Dockerfile runs `apt-get purge -y --auto-remove`. Reporting base
# findings as child findings is the exact defect
# scripts/release/assert-evidence-class.sh exists to prevent, so the evidence
# record carries package_inventory_source.kind=image-child and is validated by
# that gate before it is written anywhere durable.
#
# ONE FROZEN VULNERABILITY DATABASE for the whole run: it is downloaded once,
# its identity is recorded, and every child scan runs --skip-db-update. Findings
# are only comparable within one snapshot.
#
# Usage:
#   experimental-run.sh <cohort> <platform> --out <dir> [--only <family>]
#   experimental-run.sh --self-test          (offline; refusal paths only)
# =============================================================================
set -uo pipefail
_d="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib/common.sh
. "$_d/../lib/common.sh"
# Sourcing common.sh imports `set -e`; this script probes commands that fail on
# purpose (a build tool MUST be absent), so errexit has to go.
set +e

EXP_ROOT="${EXP_ROOT:-$(cd "$_d/../.." && pwd)}"
PLAN="$EXP_ROOT/scripts/experimental/experimental-plan.sh"

# The scanner, pinned BY DIGEST. A scanner referenced by tag can be swapped
# underneath the evidence it produced.
TRIVY_REF="aquasec/trivy:0.71.0@sha256:016eae51fdcf989332a5404af7e8f625cd5d95d7c0907a221d080a996f556500"
TRIVY_IDENTITY="aquasec/trivy@sha256:016eae51fdcf989332a5404af7e8f625cd5d95d7c0907a221d080a996f556500"

fatal() { printf 'REFUSE: %s\n' "$*" >&2; exit 1; }

# THE DAEMON THIS RUN TALKS TO, derived from the ACTIVE docker context rather
# than assumed to be /var/run/docker.sock.
#
# This is not hypothetical tidiness. On the machine this was first run on,
# /var/run/docker.sock is a symlink to one runtime while the CLI's active
# context points at ANOTHER, so syft and the containerised scanner queried a
# daemon that had never seen the images the build had just produced — and
# reported "repository does not exist", i.e. an infrastructure miss that reads
# exactly like a missing artifact. Both tools are now pointed at the same daemon
# the build used, by construction.
docker_socket() {
  local host
  host="$(docker context inspect --format '{{.Endpoints.docker.Host}}' 2>/dev/null)"
  case "$host" in
    unix://*) printf '%s' "${host#unix://}" ;;
    *) return 1 ;;
  esac
}
step()  { printf '\n--- %s\n' "$*"; }

# EXECUTION MODE DISCLOSURE.
#
# A linux/amd64 child built and probed on an aarch64 host runs under EMULATION.
# The repository already refuses to let that blur: the accepted multi-arch
# acceptance record carries execution_mode and host_architecture per child
# precisely so a QEMU result cannot later be read as native evidence (#111,
# #139). The same rule applies here, and it is DERIVED from the host rather than
# asserted, so it cannot be forgotten on a machine where it happens to be false.
host_arch() { uname -m; }
execution_mode() { # execution_mode <platform>
  local want="${1#linux/}" have; have="$(host_arch)"
  case "$have" in x86_64|amd64) have=amd64 ;; aarch64|arm64) have=arm64 ;; esac
  if [ "$want" = "$have" ]; then printf 'native'; else printf 'emulated'; fi
}

# oci_manifest_digest <local-ref> — the OCI-layout manifest digest of a locally
# built image. `docker image inspect .Id` is the CONFIG digest, not the
# manifest's, and a local tag is not an identity at all; `docker save` emits a
# real OCI layout whose index names the manifest.
oci_manifest_digest() {
  docker save "$1" 2>/dev/null | tar -xO index.json 2>/dev/null \
    | jq -r '.manifests[0].digest' 2>/dev/null
}

# base_digest_of <context-dir> — the upstream base this child was built on, read
# from the Dockerfile's single pinned base ARG.
base_digest_of() {
  grep -oE '@sha256:[0-9a-f]{64}' "$1/Dockerfile" | head -1 | tr -d '@'
}
base_ref_of() {
  grep -E '^ARG[[:space:]]+[A-Z_]*BASE=' "$1/Dockerfile" | head -1 \
    | sed -E 's/^ARG[[:space:]]+[A-Z_]*BASE="?([^"]*)"?.*/\1/'
}

# --- runtime probes, all against the RUNNING CHILD ---------------------------
php_in() { docker run --rm --entrypoint php "$1" "${@:2}"; }

# THE OPCACHE RUNTIME PROOF, and why it is not `php -m`.
#
# On the PHP 8.5 cli/fpm/worker cohort OPcache is NOT compiled: the official base
# ships it linked into the binary, and asking docker-php-ext-install to build it
# produces no shared module (policies/lifecycle.yaml, php-8.5 blocker). "Listed
# in php -m" would therefore be satisfied by a module that never caches
# anything, which is exactly the claim that must not be taken on trust.
#
# So the probe writes a REAL FILE into the container and executes it with OPcache
# on. opcache_get_status() then reports the interpreter's own view, and
# num_cached_scripts counts the probe script itself — a module that is present
# but inert cannot produce that number. It runs under --read-only with a tmpfs
# /tmp, so it also exercises the shipped confinement rather than a relaxed one.
PROBE_PHP='<?php
// A REAL FILE, compiled by OPcache inside the child. opcache_compile_file()
// returning true and num_cached_scripts rising above zero is a proof; an entry
// in php -m is not. file_update_protection is forced to 0 because OPcache
// refuses to cache a file written in the last two seconds by default, and the
// probe writes its own fixture.
file_put_contents("/tmp/zc-opcache-probe.php", "<?php function zc_probe(){ return 42; }");
$compiled = @opcache_compile_file("/tmp/zc-opcache-probe.php");
$op = function_exists("opcache_get_status") ? @opcache_get_status(false) : null;
$ext = get_loaded_extensions(false); $zend = get_loaded_extensions(true);
sort($ext); sort($zend);
echo json_encode([
  "php_version"     => PHP_VERSION,
  "php_version_id"  => PHP_VERSION_ID,
  "zend_version"    => zend_version(),
  "sapi"            => PHP_SAPI,
  "extensions"      => $ext,
  "zend_extensions" => $zend,
  "opcache_loaded"  => extension_loaded("Zend OPcache") || extension_loaded("opcache"),
  "opcache_status"  => is_array($op) ? [
      "opcache_enabled"    => $op["opcache_enabled"] ?? null,
      "compile_succeeded"  => $compiled,
      "cache_full"         => $op["cache_full"] ?? null,
      "used_memory"        => $op["memory_usage"]["used_memory"] ?? null,
      "num_cached_scripts" => $op["opcache_statistics"]["num_cached_scripts"] ?? null,
  ] : null,
  "redis_loaded"    => extension_loaded("redis"),
  "redis_version"   => phpversion("redis") ?: null,
  "redis_class"     => class_exists("Redis"),
  "redis_connect"   => method_exists("Redis", "connect"),
], JSON_UNESCAPED_SLASHES);'

# The configuration AS SHIPPED, read with no -d overrides at all. Recording the
# forced-on values from the proof run as if they were the shipped ones would be
# a small lie of exactly the kind this repository keeps paying for.
SHIPPED_PHP='<?php echo json_encode([
  "opcache.enable"     => ini_get("opcache.enable"),
  "opcache.enable_cli" => ini_get("opcache.enable_cli"),
  "opcache.jit"        => ini_get("opcache.jit"),
  "opcache.memory_consumption" => ini_get("opcache.memory_consumption"),
]);'

probe_child() { # probe_child <ref>
  printf '%s' "$PROBE_PHP" | docker run --rm -i --read-only --tmpfs /tmp \
    --entrypoint sh "$1" -c \
    'cat > /tmp/probe.php && php -d opcache.enable=1 -d opcache.enable_cli=1 \
       -d opcache.file_update_protection=0 /tmp/probe.php' 2>/dev/null
}

probe_shipped() { # probe_shipped <ref>
  printf '%s' "$SHIPPED_PHP" | docker run --rm -i --read-only --tmpfs /tmp \
    --entrypoint sh "$1" -c 'cat > /tmp/shipped.php && php /tmp/shipped.php' 2>/dev/null
}

# THE SAPI THIS IMAGE ACTUALLY SERVES WITH.
#
# Every probe above runs `php`, so every probe reports PHP_SAPI = "cli" — true of
# the probe and misleading about the artifact: php-fpm serves fpm-fcgi and
# php-frankenphp serves through an embedded server. Recording the probe's SAPI as
# the image's SAPI would be a quiet category error of the same family as
# reporting a base scan as child evidence, so the SERVING binary is asked
# directly and its answer is stored as its own field.
server_identity_of() { # server_identity_of <ref> <family>
  case "$2" in
    php-fpm)        docker run --rm --entrypoint php-fpm    "$1" -v      2>/dev/null | head -1 ;;
    php-frankenphp) docker run --rm --entrypoint frankenphp "$1" version 2>/dev/null | head -1 ;;
    *)              docker run --rm --entrypoint php        "$1" -v      2>/dev/null | head -1 ;;
  esac
}

# The extension API number is not a PHP constant; `php -i` is where it lives, and
# it is the number the whole PHP 8.5 opcache story turns on (20250925).
extension_api_of() {
  php_in "$1" -i 2>/dev/null | sed -n 's/^PHP Extension => //p' | head -1
}

run_child() { # run_child <plan-entry-json> <outdir> <revision> <db-identity>
  local e="$1" out="$2" rev="$3" db="$4"
  local fam ver ctx plat slug ckey req prov ref rc=0
  fam="$(jq -r .fam            <<<"$e")"
  ver="$(jq -r .ver            <<<"$e")"
  ctx="$(jq -r .ctx            <<<"$e")"
  plat="$(jq -r .platform      <<<"$e")"
  slug="$(jq -r .child_slug    <<<"$e")"
  ckey="$(jq -r .child_key     <<<"$e")"
  req="$(jq -r .required_extensions <<<"$e")"
  prov="$(jq -r .opcache_provenance <<<"$e")"
  ref="zenchron-experimental/${fam}:${ver}-${slug}"

  step "BUILD  $ckey  (context $ctx)"
  local t0 t1
  t0="$(date +%s)"
  # BUILD_DATE is derived from the SOURCE, not from the wall clock — the same
  # SOURCE_DATE_EPOCH rule .github/workflows/build-images.yml applies (#101). A
  # wall-clock stamp lands in a LABEL near the top of the runtime stage, so it
  # invalidates every layer after it: a re-run of the same revision would rebuild
  # from scratch and produce a different digest for identical source, which is
  # precisely what the reproducibility work exists to prevent.
  docker build --platform "$plat" \
    --build-arg "BUILD_DATE=$BUILD_DATE" \
    --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH" \
    --build-arg "VCS_REF=$rev" \
    -t "$ref" "$EXP_ROOT/$ctx" || { echo "BUILD FAILED: $ckey" >&2; return 1; }
  t1="$(date +%s)"

  local digest base bref
  digest="$(oci_manifest_digest "$ref")"
  case "$digest" in
    sha256:*) : ;;
    *) fatal "could not read an OCI-layout manifest digest for $ref; a local tag is not an identity" ;;
  esac
  base="$(base_digest_of "$EXP_ROOT/$ctx")"
  bref="$(base_ref_of "$EXP_ROOT/$ctx")"
  [ -n "$base" ] || fatal "no digest-pinned base found in $ctx/Dockerfile"

  step "IDENTITY $ckey  digest=$digest  base=$base"

  # --- PHP / SAPI identity, extensions, OPcache, redis --------------------
  step "EXTENSIONS + RUNTIME PROOFS  $ckey"
  local facts api
  facts="$(probe_child "$ref")"
  [ -n "$facts" ] || { echo "RUNTIME PROBE FAILED: $ckey" >&2; return 1; }
  jq -e . >/dev/null 2>&1 <<<"$facts" \
    || { echo "RUNTIME PROBE returned non-JSON for $ckey" >&2; return 1; }
  api="$(extension_api_of "$ref")"
  local shipped
  shipped="$(probe_shipped "$ref")"
  jq -e . >/dev/null 2>&1 <<<"$shipped" \
    || { echo "AS-SHIPPED PROBE returned non-JSON for $ckey" >&2; return 1; }
  local server_id
  server_id="$(server_identity_of "$ref" "$fam")"
  [ -n "$server_id" ] || { echo "SERVER IDENTITY PROBE FAILED: $ckey" >&2; return 1; }
  facts="$(jq -c --arg a "$api" --argjson sh "$shipped" --arg srv "$server_id" \
             '. + {extension_api:$a, opcache_as_shipped:$sh,
                   probe_sapi:.sapi, server_identity:$srv}
              | del(.sapi)' <<<"$facts")"

  # The proof must be a PROOF. A record that says "opcache present" while
  # opcache_get_status() reports nothing cached is the same species of claim as
  # reporting a base scan as child evidence.
  local op_enabled op_cached
  op_enabled="$(jq -r '.opcache_status.opcache_enabled // false' <<<"$facts")"
  op_cached="$(jq -r '.opcache_status.num_cached_scripts // 0' <<<"$facts")"
  local op_compiled
  op_compiled="$(jq -r '.opcache_status.compile_succeeded // false' <<<"$facts")"
  if [ "$op_enabled" != true ] || [ "$op_compiled" != true ] || [ "${op_cached:-0}" -lt 1 ]; then
    echo "OPCACHE RUNTIME PROOF FAILED for $ckey: enabled=$op_enabled compiled=$op_compiled cached=$op_cached" >&2
    rc=1
  fi
  # redis likewise: a loaded extension that cannot produce its client class is
  # not a working redis.
  if [ "$(jq -r '.redis_loaded' <<<"$facts")" != true ] \
     || [ "$(jq -r '.redis_class' <<<"$facts")" != true ]; then
    echo "REDIS RUNTIME PROOF FAILED for $ckey" >&2
    rc=1
  fi


  # required-extension check, against the COHORT's declared set
  local missing
  missing="$(php_in "$ref" -r '
    $req = preg_split("/\s+/", trim($argv[1]));
    $norm = [];
    foreach (array_merge(get_loaded_extensions(false), get_loaded_extensions(true)) as $l) {
      $norm[strtolower($l)] = true;
      if (strpos(strtolower($l), "zend ") === 0) { $norm[substr(strtolower($l), 5)] = true; }
    }
    $m = [];
    foreach ($req as $r) { if ($r !== "" && !isset($norm[strtolower($r)])) { $m[] = $r; } }
    echo implode(" ", $m);' "$req" 2>/dev/null)"
  if [ -n "$missing" ]; then
    echo "EXTENSION CONTRACT FAILED for $ckey: missing [$missing]" >&2
    rc=1
  fi

  # --- installed-package inventory: THE 241-vs-47 FIELD -------------------
  step "PACKAGE INVENTORY (CHILD, never the base)  $ckey"
  local pkgfile pkgsha pkgcount
  pkgfile="$out/${slug}.packages.txt"
  docker run --rm --entrypoint dpkg-query "$ref" -W -f '${Package}\t${Version}\n' \
    2>/dev/null | LC_ALL=C sort > "$pkgfile"
  pkgcount="$(grep -c . "$pkgfile")"
  [ "$pkgcount" -gt 0 ] || { echo "EMPTY PACKAGE INVENTORY: $ckey" >&2; return 1; }
  pkgsha="$(shasum -a 256 "$pkgfile" | awk '{print $1}')"

  # --- build-tool purge proof, by EXECUTION not by listing ----------------
  step "BUILD-TOOL PURGE PROOF  $ckey"
  local tool purged="[]" tools_present=""
  for tool in $(jq -r '.forbidden_tools[]' <<<"$e"); do
    if docker run --rm --entrypoint sh "$ref" -c "command -v $tool" >/dev/null 2>&1; then
      tools_present="$tools_present $tool"
    else
      purged="$(jq -c --arg t "$tool" '. + [$t]' <<<"$purged")"
    fi
  done
  if [ -n "$tools_present" ]; then
    echo "BUILD TOOLS SURVIVED in $ckey:$tools_present" >&2
    rc=1
  fi

  # --- runtime smoke, reusing the production per-family smoke script ------
  step "SMOKE  $ckey"
  local smoke_rc=0
  bash "$EXP_ROOT/scripts/smoke/smoke-${fam}.sh" "$ref" > "$out/${slug}.smoke.txt" 2>&1 || smoke_rc=$?
  tail -1 "$out/${slug}.smoke.txt"

  # --- SBOM ---------------------------------------------------------------
  step "SBOM  $ckey"
  DOCKER_HOST="unix://$DOCKER_SOCK" \
  syft "docker:$ref" -c "$EXP_ROOT/policies/syft.yaml" \
       -o "spdx-json=$out/${slug}.spdx.json" > "$out/${slug}.sbom.log" 2>&1 \
    || { echo "SBOM FAILED: $ckey (see ${slug}.sbom.log)" >&2; return 1; }
  local sbom_pkgs sbom_sha
  sbom_pkgs="$(jq '.packages|length' "$out/${slug}.spdx.json")"
  sbom_sha="$(shasum -a 256 "$out/${slug}.spdx.json" | awk '{print $1}')"

  # --- vulnerability scan of the CHILD, frozen database -------------------
  step "SCAN (CHILD)  $ckey"
  docker run --rm \
    -v "$DOCKER_SOCK":/var/run/docker.sock \
    -v "$TRIVY_CACHE":/root/.cache \
    "$TRIVY_REF" image \
      --severity CRITICAL,HIGH --exit-code 0 --scanners vuln \
      --skip-db-update --skip-java-db-update \
      --skip-dirs /usr/share/java,/usr/share/maven-repo \
      --format json "$ref" > "$out/${slug}.trivy.json" 2>"$out/${slug}.trivy.log"
  jq -e '.Results' "$out/${slug}.trivy.json" >/dev/null 2>&1 \
    || { echo "SCAN FAILED: $ckey (see ${slug}.trivy.log)" >&2; return 1; }

  local scan_sha
  scan_sha="$(shasum -a 256 "$out/${slug}.trivy.json" | awk '{print $1}')"
  # A COMPACTED, REVIEWABLE finding set. The raw Trivy report is ~600 KB of
  # scanner internals per child; what a reviewer needs is the tuple that decides
  # governance — advisory, package, installed version, fixed version, severity.
  # The full report stays bound by scan_sha above rather than being committed.
  jq --arg ck "$ckey" '{
       child_key: $ck,
       findings: [.Results[]?.Vulnerabilities[]?
         | {cve:.VulnerabilityID, package:.PkgName, installed:.InstalledVersion,
            fixed:(.FixedVersion // null), severity:.Severity,
            source:(.DataSource.ID // null)}]
         | sort_by(.cve, .package)
     }' "$out/${slug}.trivy.json" > "$out/${slug}.findings.json"

  local crit high by_pkg
  crit="$(jq '[.Results[]?.Vulnerabilities[]?|select(.Severity=="CRITICAL")]|length' "$out/${slug}.trivy.json")"
  high="$(jq '[.Results[]?.Vulnerabilities[]?|select(.Severity=="HIGH")]|length' "$out/${slug}.trivy.json")"
  by_pkg="$(jq -c '[.Results[]?.Vulnerabilities[]?|.PkgName]|group_by(.)|map({key:.[0],value:length})|from_entries' \
              "$out/${slug}.trivy.json")"
  # linux-libc-dev is named explicitly whether or not it is present: it is the
  # package that makes the base and the child visibly different classes.
  by_pkg="$(jq -c 'if has("linux-libc-dev") then . else . + {"linux-libc-dev":0} end' <<<"$by_pkg")"

  # --- the classed evidence record ----------------------------------------
  # Schema-clean: schemas/evidence-class-v1.schema.json sets
  # additionalProperties:false, so every richer fact goes in the companion
  # child-facts file rather than being bolted onto a shared schema.
  step "EVIDENCE  $ckey"
  jq -n --arg cls foundry-child --arg dig "$digest" --arg ck "$ckey" \
        --arg plat "$plat" --arg fam "$fam" --arg ver "$ver" --arg rev "$rev" \
        --arg bid "$(jq -r .build_input_digest <<<"$e")" \
        --arg scanner "$TRIVY_IDENTITY" --arg db "$db" \
        --arg psha "$pkgsha" --argjson pcount "$pkgcount" \
        --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        --arg base "$base" --arg bref "$bref" \
        --argjson crit "$crit" --argjson high "$high" --argjson bypkg "$by_pkg" '
    {schema_version:1, evidence_class:$cls, image_digest:$dig, child_key:$ck,
     platform:$plat, image_family:$fam, image_version:$ver, source_revision:$rev,
     build_input_digest:$bid, build_completed:true, scanner_identity:$scanner,
     vulnerability_db_identity:$db, created_at:$created,
     package_inventory_source:{kind:"image-child", sha256:$psha, package_count:$pcount},
     parent:{evidence_class:"upstream-base", image_digest:$base, reference:$bref},
     severity_counts:{CRITICAL:$crit, HIGH:$high},
     findings_by_package:$bypkg}' > "$out/${slug}.evidence.json"

  # VALIDATED BY THE EXISTING GATE, REUSED. If the record cannot be classified
  # as a foundry-child it is not written into the audit set.
  bash "$EXP_ROOT/scripts/release/assert-evidence-class.sh" \
       require-class foundry-child "$out/${slug}.evidence.json" \
    || fatal "the generated record for $ckey is not valid foundry-child evidence"
  bash "$EXP_ROOT/scripts/release/assert-evidence-class.sh" \
       consumer governance-generation "$out/${slug}.evidence.json" >/dev/null \
    || fatal "governance-generation refuses the record for $ckey"

  # --- the companion facts file -------------------------------------------
  jq -n --arg ck "$ckey" --arg ref "$ref" --arg dig "$digest" --arg ctx "$ctx" \
        --arg bid "$(jq -r .build_input_digest <<<"$e")" \
        --arg base "$base" --arg bref "$bref" --arg rev "$rev" \
        --arg prov "$prov" --arg req "$req" --arg missing "$missing" \
        --argjson facts "$facts" --argjson purged "$purged" \
        --arg exec "$(execution_mode "$plat")" --arg harch "$(host_arch)" \
        --argjson build_seconds "$(( t1 - t0 ))" \
        --argjson smoke_rc "$smoke_rc" --argjson sbom_pkgs "$sbom_pkgs" \
        --arg sbom_sha "$sbom_sha" --arg scan_sha "$scan_sha" \
        --argjson pcount "$pkgcount" --arg psha "$pkgsha" '
    {child_key:$ck, local_reference:$ref, oci_manifest_digest:$dig,
     build_context:$ctx, build_input_digest:$bid, source_revision:$rev,
     execution_mode:$exec, host_architecture:$harch,
     upstream_base:{reference:$bref, digest:$base},
     build_seconds:$build_seconds,
     php:$facts,
     opcache:{declared_provenance:$prov,
              loaded:$facts.opcache_loaded,
              as_shipped:$facts.opcache_as_shipped,
              runtime_proof:$facts.opcache_status,
              proof_method:"a real file written and compiled inside the child under --read-only with a tmpfs /tmp; opcache.enable/enable_cli forced on for the proof only, opcache.file_update_protection=0 so a just-written file is cacheable. opcache_compile_file() returning true AND num_cached_scripts > 0 is the proof; presence in php -m is not."},
     redis:{loaded:$facts.redis_loaded, version:$facts.redis_version,
            class_present:$facts.redis_class},
     extensions:{required:($req|split(" ")), missing:(if $missing=="" then [] else ($missing|split(" ")) end),
                 loaded:$facts.extensions, zend:$facts.zend_extensions},
     build_tools_purged:$purged,
     packages:{inventory_sha256:$psha, count:$pcount, source:"dpkg-query on the CHILD"},
     sbom:{format:"spdx-json", package_count:$sbom_pkgs, sha256:$sbom_sha,
           note:"the full SPDX document is a build artifact, not committed: 2.7 MB per child of material regenerable from oci_manifest_digest. It is BOUND here by sha256, which is what evidence needs."},
     scan:{full_report_sha256:$scan_sha,
           note:"the raw scanner report is likewise bound rather than committed; the reviewable tuple set is in the sibling findings.json"},
     smoke:{exit_code:$smoke_rc, result:(if $smoke_rc==0 then "PASS" else "FAIL" end)}}' \
    > "$out/${slug}.child-facts.json"

  [ "$smoke_rc" -eq 0 ] || rc=1
  return "$rc"
}

main() {
  local cohort="${1-}" plat="${2-}" out="" only=""
  shift 2 2>/dev/null
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --out)  out="${2-}"; shift 2 ;;
      --only) only="${2-}"; shift 2 ;;
      *) fatal "unknown option '$1'" ;;
    esac
  done
  [ -n "$cohort" ] || fatal "no cohort named"
  [ -n "$plat" ]   || fatal "no platform named"
  [ -n "$out" ]    || fatal "--out <dir> is required: this runner never chooses a
        destination for you, because a default output path is how evidence ends
        up written somewhere nobody reviews"
  command -v docker >/dev/null || fatal "docker is required"
  command -v syft   >/dev/null || fatal "syft is required"
  command -v jq     >/dev/null || fatal "jq is required"

  # EVERY capability is asserted against the plan BEFORE anything runs. The plan
  # is the authority; this runner never decides what it may do.
  local cap
  for cap in build smoke extensions sbom scan evidence; do
    bash "$PLAN" capability "$cohort" "$cap" >/dev/null || exit 1
  done

  local plan
  plan="$(bash "$PLAN" plan "$cohort" "$plat")" || exit 1

  local rev
  rev="$(git -C "$EXP_ROOT" rev-parse HEAD)"
  is_hex40 "$rev" || fatal "source revision '$rev' is not 40 lowercase hex"

  SOURCE_DATE_EPOCH="$(git -C "$EXP_ROOT" show -s --format=%ct "$rev")"
  case "$SOURCE_DATE_EPOCH" in
    ''|*[!0-9]*) fatal "could not derive SOURCE_DATE_EPOCH from $rev" ;;
  esac
  BUILD_DATE="$(TZ=UTC0 date -u -r "$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null \
                || date -u -d "@$SOURCE_DATE_EPOCH" +%Y-%m-%dT%H:%M:%SZ)"
  export SOURCE_DATE_EPOCH BUILD_DATE

  DOCKER_SOCK="$(docker_socket)" \
    || fatal "the active docker context does not expose a unix socket; syft and
        the containerised scanner must reach the SAME daemon the build used"
  export DOCKER_SOCK

  mkdir -p "$out"

  # --- ONE FROZEN DATABASE for the whole run ------------------------------
  TRIVY_CACHE="${TRIVY_CACHE:-$out/.trivy-cache}"
  export TRIVY_CACHE
  mkdir -p "$TRIVY_CACHE"
  step "FREEZING THE VULNERABILITY DATABASE (downloaded once, shared by all children)"
  docker run --rm -v "$TRIVY_CACHE":/root/.cache "$TRIVY_REF" \
    image --download-db-only >/dev/null 2>&1 \
    || fatal "could not download the vulnerability database"
  local db
  # The cache ROOT is mounted at /root/.cache, so trivy's own metadata lands at
  # <root>/trivy/db/metadata.json — not <root>/db/metadata.json. Reading the
  # wrong path would silently yield an empty identity, which is why this is a
  # refusal below rather than a default.
  db="$(jq -r '"trivy-db:v" + (.Version|tostring) + "+updated:" + .UpdatedAt' \
        "$TRIVY_CACHE/trivy/db/metadata.json" 2>/dev/null)"
  case "$db" in
    trivy-db:v*) : ;;
    *) fatal "could not read the frozen database identity from the trivy cache" ;;
  esac
  echo "frozen database: $db"

  jq -n --arg db "$db" --arg scanner "$TRIVY_IDENTITY" --arg rev "$rev" \
        --arg cohort "$cohort" --arg plat "$plat" \
        --arg exec "$(execution_mode "$plat")" --arg harch "$(host_arch)" \
        --arg created "$(date -u +%Y-%m-%dT%H:%M:%SZ)" '
    {cohort:$cohort, platform:$plat, source_revision:$rev,
     scanner_identity:$scanner, vulnerability_db_identity:$db,
     frozen_at:$created, execution_mode:$exec, host_architecture:$harch,
     note:"ONE database snapshot, downloaded once and shared by every child in this run. Findings are only comparable within one snapshot."}' \
    > "$out/frozen-scan-basis.json"

  local n=0 failed=""
  while IFS= read -r e; do
    [ -n "$e" ] || continue
    if [ -n "$only" ] && [ "$(jq -r .fam <<<"$e")" != "$only" ]; then continue; fi
    n=$(( n + 1 ))
    run_child "$e" "$out" "$rev" "$db" || failed="$failed $(jq -r .child_key <<<"$e")"
  done < <(printf '%s' "$plan" | jq -c '.include[]')

  [ "$n" -gt 0 ] || fatal "the plan enumerated no children to run"

  # THE DURABLE SET, named explicitly.
  #
  # `shasum ./*.json` would also cover the per-child SPDX documents and raw
  # scanner reports — ~3.3 MB per child of regenerable material that is bound by
  # sha256 inside each child-facts record instead of being committed. A
  # SHA256SUMS covering files the audit directory does not carry cannot be
  # verified by anyone reading that directory, which is worse than no checksum.
  ( cd "$out" && shasum -a 256 \
      frozen-scan-basis.json \
      ./*.evidence.json ./*.child-facts.json ./*.findings.json \
      ./*.packages.txt ./*.smoke.txt > SHA256SUMS )

  echo
  echo "================================================================"
  printf 'experimental run: %d child(ren), cohort=%s platform=%s\n' "$n" "$cohort" "$plat"
  if [ -n "$failed" ]; then
    printf 'FAILED:%s\n' "$failed"
    return 1
  fi
  echo "all children completed"
}

# --- self-test ---------------------------------------------------------------
# OFFLINE and DOCKER-FREE by construction: it exercises the refusal paths only.
# Writes nothing outside a disposable fixture.
self_test() {
  local pass=0 fail=0 tmp
  tmp="$(mktemp -d)"
  # EXIT, never RETURN (tests/lib/test_functrace_safety.sh).
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" EXIT
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }
  # Captured, never piped into a quiet matcher: the producer fails on purpose and
  # a matcher that exits early would kill it with SIGPIPE (exit 141).
  says() { case "$("$0" "$@" 2>&1)" in *"$SAY"*) return 0 ;; *) return 1 ;; esac; }

  ck "a missing --out is refused" "! $0 php-8.5 linux/amd64 >/dev/null 2>&1"
  SAY="never chooses a" ck "...because a default destination is how evidence goes unreviewed" \
     "says php-8.5 linux/amd64"
  SAY="no cohort named" ck "a missing cohort is refused" "says '' linux/amd64 --out '$tmp/o'"
  SAY="no platform named" ck "a missing platform is refused" "says php-8.5 '' --out '$tmp/o'"
  SAY="unknown option" ck "an unknown option is refused" \
     "says php-8.5 linux/amd64 --out '$tmp/o' --publish"
  # The runner never decides what it may do: an unauthorized platform is refused
  # by the PLAN, before docker is ever consulted.
  SAY="has ever been built" ck "an unauthorized platform is refused BY THE PLAN, before any build" \
     "says php-8.5 linux/arm64 --out '$tmp/o'"
  ck "...and nothing was written to the output directory" "[ ! -d '$tmp/o' ]"
  SAY="is not a registered experimental cohort" ck "an unregistered cohort is refused" \
     "says php-9.9 linux/amd64 --out '$tmp/o'"
  ck "the runner has no image list of its own (it cannot enumerate)" \
     "! grep -vE '^[[:space:]]*#' '$0' | grep -qE 'php-(cli|fpm|worker|frankenphp)/8'"
  ck "...and it reads every child from the plan" "grep -q 'bash \"\$PLAN\" plan' '$0'"

  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

# NO ARGUMENT is a usage error; an EMPTY first argument is a refusal. They are
# different, and the difference is what tells a caller whether they mistyped the
# command or passed an unset variable.
if [ "$#" -eq 0 ]; then
  echo "usage: $(basename "$0") <cohort> <platform> --out <dir> [--only <family>]" >&2
  exit 64
fi
case "$1" in
  --self-test) self_test ;;
  *)           main "$@" ;;
esac
