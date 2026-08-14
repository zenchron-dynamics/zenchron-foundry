#!/usr/bin/env bash
# =============================================================================
# scripts/assert-no-java-artifacts.sh <image-ref>
# -----------------------------------------------------------------------------
# Refuse an image whose final filesystem contains a Java artifact.
#
# WHY THIS EXISTS. Every child is scanned with:
#
#     --skip-java-db-update --skip-dirs /usr/share/java,/usr/share/maven-repo
#
# because Trivy's jar analyzer would otherwise demand a 905 MiB / 1.5 GB Java
# database to look up four gettext-base libintl jars that arrive in the nginx
# BASE layer and are deleted in the final image. Fetching that database broke
# run 31701249058 and run 31749810234.
#
# The skip is applied to the whole matrix, but the build-time refusal that made
# it safe lived only in images/nginx/Dockerfile. A php image could therefore
# have acquired a real Java artifact under one of those paths and the scan would
# have skipped it. This closes that gap by asserting the invariant the skip
# depends on, for EVERY image, at the point the release path evaluates them.
#
# HOW. The filesystem is listed from OUTSIDE the image: `docker create` plus
# `docker export` piped straight into `tar -t`. Nothing is required inside the
# image — no shell, no find — so this keeps working if an image is ever
# slimmed to distroless, and it cannot be fooled by a broken interpreter.
# Nothing is written to disk; the export is streamed.
#
# FAILS CLOSED. An image that cannot be created, exported or listed is REFUSED,
# not skipped. "Could not determine" is not "no Java artifacts".
#
# Usage:
#   assert-no-java-artifacts.sh <image-ref>
#   assert-no-java-artifacts.sh --self-test
# =============================================================================
set -uo pipefail

# Extensions Trivy's jar analyzer recognises. Keep in step with the analyzer:
# an extension it scans but this refuses to look for is a gap in exactly the
# direction that matters.
JAVA_RE='\.(jar|war|ear|par|jmod)$'

assert_image() {
  local ref="$1"
  command -v docker >/dev/null 2>&1 || { echo "REFUSE: docker unavailable; cannot verify $ref" >&2; return 1; }

  local cid
  cid="$(docker create "$ref" 2>/dev/null)" || {
    echo "REFUSE: could not create a container from $ref" >&2; return 1; }
  # shellcheck disable=SC2064
  trap "docker rm -f '$cid' >/dev/null 2>&1 || true" RETURN

  # `docker export | tar -t` — the exit status that matters is the EXPORT's, so
  # capture the pipeline's parts explicitly rather than trusting $? of the tail.
  local listing status
  listing="$(set -o pipefail; docker export "$cid" 2>/dev/null | tar -t 2>/dev/null)"
  status=$?
  if [ "$status" -ne 0 ] || [ -z "$listing" ]; then
    echo "REFUSE: could not list the filesystem of $ref (export/tar failed)" >&2
    return 1
  fi

  local hits
  hits="$(printf '%s\n' "$listing" | grep -iE "$JAVA_RE" || true)"
  if [ -n "$hits" ]; then
    echo "REFUSE: $ref ships Java artifacts, so the scan's --skip-dirs is unsafe:" >&2
    printf '%s\n' "$hits" | sed 's/^/  /' >&2
    return 1
  fi

  printf 'ok - no Java artifacts in %s (%s paths inspected)\n' \
         "$ref" "$(printf '%s\n' "$listing" | wc -l | tr -d ' ')"
}

self_test() {
  local pass=0 fail=0
  ck() { if eval "$2"; then pass=$((pass+1)); echo "ok   - $1"; else fail=$((fail+1)); echo "FAIL - $1"; fi; }

  # The matcher is the whole check; test it directly rather than building images.
  match() { printf '%s\n' "$1" | grep -iE "$JAVA_RE" >/dev/null; }

  ck "a jar is caught"                  'match usr/share/java/libintl.jar'
  ck "a war is caught"                  'match opt/app/foo.war'
  ck "an ear is caught"                 'match srv/x.ear'
  ck "a par is caught"                  'match srv/x.par'
  ck "a jmod is caught"                 'match usr/lib/jvm/x.jmod'
  ck "case is ignored"                  'match usr/share/java/LibIntl.JAR'
  ck "a jar under maven-repo is caught" 'match usr/share/maven-repo/org/gnu/gettext/libintl/0.21/libintl-0.21.jar'
  # Substring false positives would make this refuse honest images.
  ck "jarfile is NOT a jar"             '! match usr/bin/jarfile'
  ck "a .jar. mid-path is not a match"  '! match usr/lib/x.jar.txt'
  ck "an ordinary binary is not"        '! match usr/sbin/nginx'
  ck "war in a directory name is not"   '! match var/lib/software/warehouse'

  # Fail-closed behaviour on an image that cannot be inspected.
  ck "a nonexistent image is REFUSED" \
     '! assert_image zenchron-nonexistent-image:definitely-not-here 2>/dev/null'

  echo "----"
  printf 'self-test: %d ok, %d failed\n' "$pass" "$fail"
  [ "$fail" -eq 0 ]
}

case "${1:-}" in
  --self-test) self_test ;;
  "")          echo "usage: $(basename "$0") <image-ref> | --self-test" >&2; exit 64 ;;
  *)           assert_image "$1" ;;
esac
