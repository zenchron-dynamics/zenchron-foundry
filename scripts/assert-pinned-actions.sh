#!/usr/bin/env bash
# =============================================================================
# assert-pinned-actions.sh
# -----------------------------------------------------------------------------
# Fails if ANY GitHub Action `uses:` reference is not pinned to a full
# 40-hex-char commit SHA.
#
# Accepted:
#   uses: owner/repo@<40-hex-sha>            (optional trailing "# vX" comment)
#   uses: owner/repo/path@<40-hex-sha>       (subpath actions)
#   uses: ./.github/workflows/foo.yml        (LOCAL reusable workflow -- exempt)
#
# Rejected (printed as <file>:<lineno>: <ref>):
#   @vN, @vN.N.N, @main, @master, branch names, short SHAs, any non-40-hex ref
#
# Scans workflows, composite actions, and reusable workflow files.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

violations=0

# Collect target files: workflows + composite/reusable action definitions.
files=()
while IFS= read -r f; do
  [[ -n "${f}" ]] && files+=("${f}")
done < <(
  {
    find "${ROOT}/.github/workflows" -type f \( -name '*.yml' -o -name '*.yaml' \) 2>/dev/null || true
    find "${ROOT}/.github/actions" -type f \( -name 'action.yml' -o -name 'action.yaml' \) 2>/dev/null || true
  } | sort -u
)

if [[ "${#files[@]}" -eq 0 ]]; then
  echo "WARN: no workflow or action files found under .github" >&2
  echo "RESULT: PASS (nothing to check)"
  exit 0
fi

for file in "${files[@]}"; do
  [[ -f "${file}" ]] || continue
  while IFS= read -r entry; do
    lineno="${entry%%:*}"
    rest="${entry#*:}"

    # Isolate the value after "uses:" and strip surrounding noise.
    ref="$(sed -E 's/.*uses:[[:space:]]*//' <<<"${rest}")"
    ref="${ref%%#*}"                      # drop trailing "# vX" comment
    ref="${ref//\"/}"                     # drop quotes
    ref="${ref//\'/}"                     # drop single quotes
    ref="$(sed -E 's/[[:space:]]+$//' <<<"${ref}")"

    [[ -z "${ref}" ]] && continue

    # Local reusable workflow / local action references are exempt.
    if [[ "${ref}" == ./* ]]; then
      continue
    fi
    # Docker-based action references (docker://) are out of scope here.
    if [[ "${ref}" == docker://* ]]; then
      continue
    fi

    # Must be owner/repo[/path]@<40 lowercase hex>.
    if [[ "${ref}" =~ ^[^@/]+/[^@]+@[0-9a-f]{40}$ ]]; then
      continue
    fi

    printf '%s:%s: %s\n' "${file}" "${lineno}" "${ref}"
    violations=$((violations + 1))
  done < <(grep -nE '^[[:space:]]*-?[[:space:]]*uses:[[:space:]]*' "${file}" || true)
done

echo
if [[ "${violations}" -gt 0 ]]; then
  printf 'RESULT: FAIL (%d unpinned action reference(s))\n' "${violations}"
  exit 1
fi
echo "RESULT: PASS (all action references SHA-pinned)"
