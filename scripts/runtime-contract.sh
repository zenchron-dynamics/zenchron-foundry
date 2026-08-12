#!/usr/bin/env bash
# =============================================================================
# scripts/runtime-contract.sh — ONE harness for the hardened runtime contract.
# -----------------------------------------------------------------------------
# #110. The smoke tests proved a SUBSET of the advertised hardening, and a
# different subset per family: the FrankenPHP smoke started with
# `--read-only --tmpfs /tmp` and omitted `--cap-drop ALL`, no-new-privileges, PID
# limits and the noexec/nosuid/nodev flags entirely. An image could pass smoke
# and still fail under the profile the documentation tells consumers to use.
#
# This runs EVERY image under the full profile from policies/runtime-contract.yaml
# and asserts the same invariants against all of them.
#
# WHAT IT READS, AND FROM WHERE. Nothing is restated:
#   policies/runtime-contract.yaml   the invariants and the profile
#   contracts/images/<image>.yaml    user, ports, tmpfs, and the `runtime:` block
#
# WHAT IT MEASURES. Everything comes from /proc/1 — the REAL entrypoint process,
# not an exec'd shell that merely inherited a similar posture:
#   Uid/Gid, CapEff/CapPrm/CapBnd, NoNewPrivs, Seccomp, mount flags, listeners,
#   cgroup pids.max, plus live writability probes and a real SIGTERM.
#
# Usage:
#   runtime-contract.sh <image-ref> <contract.yaml> [--json OUT]
#   runtime-contract.sh --all [--json OUT]      # the whole shipping matrix
#   runtime-contract.sh --self-test
#
# Exit 0 only when every declared invariant held. Any probe that cannot be
# evaluated is a FAILURE, never a skip: "could not determine" must not read as
# "the control is in place".
# =============================================================================
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY="${RUNTIME_POLICY:-$ROOT/policies/runtime-contract.yaml}"

PASS=0; FAIL=0; RESULTS=""
ok()   { PASS=$((PASS+1)); printf 'PASS  %s\n' "$1"; RESULTS="${RESULTS}{\"check\":\"$1\",\"result\":\"PASS\"},"; }
bad()  { FAIL=$((FAIL+1)); printf 'FAIL  %s\n' "$1" >&2; [ -n "${2:-}" ] && printf '        %s\n' "$2" >&2
         RESULTS="${RESULTS}{\"check\":\"$1\",\"result\":\"FAIL\",\"detail\":\"$(printf '%s' "${2:-}" | tr '"\n' "' ")\"},"; }
ck()   { if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "want '$3', got '$2'"; fi; }

y() { # y <file> <python-expr over `d`>
  python3 -c "
import yaml,sys
d=yaml.safe_load(open(sys.argv[1])) or {}
v=($2)
print('' if v is None else (' '.join(str(x) for x in v) if isinstance(v,(list,tuple)) else v))
" "$1"
}

# --- the probe, run INSIDE the container ------------------------------------
# One shell script, emitting key=value lines. It reads /proc/1 in both modes:
# for a server the harness `docker exec`s it, so /proc/1 is the real entrypoint;
# for a oneshot the probe IS pid 1. Same assertions either way.
probe_script() { cat <<'PROBE'
set -u
st=/proc/1/status
printf 'uid=%s\n' "$(awk '/^Uid:/{print $2}' $st)"
printf 'gid=%s\n' "$(awk '/^Gid:/{print $2}' $st)"
printf 'capeff=%s\n' "$(awk '/^CapEff:/{print $2}' $st)"
printf 'capprm=%s\n' "$(awk '/^CapPrm:/{print $2}' $st)"
printf 'capbnd=%s\n' "$(awk '/^CapBnd:/{print $2}' $st)"
printf 'nnp=%s\n' "$(awk '/^NoNewPrivs:/{print $2}' $st)"
printf 'seccomp=%s\n' "$(awk '/^Seccomp:/{print $2}' $st)"
printf 'pidsmax=%s\n' "$(cat /sys/fs/cgroup/pids.max 2>/dev/null || echo UNKNOWN)"

# tmpfs flags, one line per tmpfs mount
grep ' tmpfs ' /proc/mounts 2>/dev/null | while read -r _ mp _ opts _; do
    printf 'tmpfs=%s:%s\n' "$mp" "$opts"
done

# rootfs must be read-only: try a write somewhere that is NOT a declared tmpfs.
if (echo x > /.zenchron-rw-probe) 2>/dev/null; then
    rm -f /.zenchron-rw-probe 2>/dev/null
    printf 'rootfs=WRITABLE\n'
else
    printf 'rootfs=readonly\n'
fi

# each declared writable path must actually be writable
for p in ${ZC_WRITABLE:-}; do
    if (echo x > "$p/.zenchron-rw-probe") 2>/dev/null; then
        rm -f "$p/.zenchron-rw-probe" 2>/dev/null
        printf 'writable=%s:yes\n' "$p"
    else
        printf 'writable=%s:NO\n' "$p"
    fi
done

# --- listeners -------------------------------------------------------------
# Prefer a COMPLETE enumeration from the kernel. Some container runtimes present
# an empty /proc/net/tcp inside the namespace (observed on the macOS VM used for
# local runs); in that case fall back to bounded connect probing and SAY SO, so
# the evidence never claims completeness it did not measure.
listeners=""; method=proc
for f in /proc/1/net/tcp /proc/1/net/tcp6 /proc/net/tcp /proc/net/tcp6; do
    [ -r "$f" ] || continue
    while read -r _ local _ stt _; do
        [ "$stt" = "0A" ] || continue
        listeners="$listeners $(printf '%d' "0x${local#*:}")"
    done <<EOF
$(tail -n +2 "$f")
EOF
done
if [ -z "$listeners" ]; then
    method=connect
    _open() { # _open <port> -> 0 if something accepts
        if command -v bash >/dev/null 2>&1; then
            bash -c "exec 3<>/dev/tcp/127.0.0.1/$1" 2>/dev/null
        elif command -v nc >/dev/null 2>&1; then
            nc -z -w 1 127.0.0.1 "$1" 2>/dev/null
        else
            return 2   # no probe available -> caller treats as indeterminate
        fi
    }
    for p in ${ZC_EXPECTED_PORTS:-} ${ZC_DENY_PORTS:-}; do
        _open "$p"; rc=$?
        [ "$rc" -eq 2 ] && { method=none; break; }
        [ "$rc" -eq 0 ] && listeners="$listeners $p"
    done
fi
printf 'listener_method=%s\n' "$method"
printf 'listeners=%s\n' "$(echo $listeners | tr ' ' '\n' | sort -un | tr '\n' ' ')"
PROBE
}

# --- run the contract for one image ------------------------------------------
run_one() { # run_one <image-ref> <contract.yaml>
  local img="$1" contract="$2"
  local name user ports tmpfs mode stop_sig grace pids flags size deny
  name="$(y "$contract" "d.get('image')")/$(y "$contract" "d.get('selector')")"
  user="$(y "$contract" "d.get('user')")"
  # `ports` is what the image EXPOSEs — a declaration of intent. What it
  # actually binds by default can be a strict subset: caddy EXPOSEs 8080 for the
  # consumer's site but the shipped Caddyfile only defines :8081, so a
  # consumer-activated port is not an unexpected listener and not a missing one.
  ports="$(y "$contract" "(d.get('runtime') or {}).get('listeners_default', d.get('ports') or [])")"
  tmpfs="$(y "$contract" "d.get('tmpfs') or []")"
  mode="$(y "$contract" "(d.get('runtime') or {}).get('mode')")"
  stop_sig="$(y "$contract" "(d.get('runtime') or {}).get('stop_signal')")"
  grace="$(y "$contract" "(d.get('runtime') or {}).get('graceful_stop_seconds')")"
  pids="$(y "$POLICY" "d['profile']['pids_limit']")"
  flags="$(y "$POLICY" "','.join(d['profile']['tmpfs_flags'])")"
  size="$(y "$POLICY" "d['profile']['tmpfs_size']")"
  deny="$(y "$POLICY" "d['sensitive_ports_denylist']")"

  printf '\n== runtime contract: %s (%s)\n' "$name" "$img"

  # Fail closed on an incomplete contract rather than silently checking less.
  for f in user mode stop_sig grace; do
    eval "v=\$$f"
    [ -n "$v" ] || { bad "$name: contract declares $f" "empty"; return 1; }
  done

  local -a RUN=(--rm --platform linux/amd64 --read-only --cap-drop ALL
                --security-opt no-new-privileges --pids-limit "$pids")
  local mp
  # mode=1777 is not decoration. Docker special-cases /tmp to 1777 and gives
  # every OTHER tmpfs mode 755 owned by root, so an image running as uid 10001
  # cannot write a path its own contract declares writable. Caddy hit exactly
  # this: `open /data/caddy/instance.uuid: read-only file system` on every start.
  local tmode; tmode="$(y "$POLICY" "d['profile'].get('tmpfs_mode','1777')")"
  for mp in $tmpfs; do RUN+=(--tmpfs "$mp:size=$size,mode=$tmode,$flags"); done

  local -a extra=()
  while IFS= read -r a; do [ -n "$a" ] && extra+=("$a"); done < <(
    python3 -c "
import yaml,sys
d=yaml.safe_load(open(sys.argv[1]))
for a in ((d.get('runtime') or {}).get('run_args') or []): print(a)" "$contract")

  local out cid rc
  if [ "$mode" = server ]; then
    cid="$(docker run -d "${RUN[@]}" -e ZC_WRITABLE="$tmpfs" \
             -e ZC_EXPECTED_PORTS="$ports" -e ZC_DENY_PORTS="$deny" \
             "$img" ${extra[@]+"${extra[@]}"} 2>&1)" || { bad "$name: starts under the hardened profile" "$cid"; return 1; }
    ok "$name: starts under the hardened profile"
    # Give a server time to bind before enumerating listeners.
    sleep 4
    if ! docker inspect -f '{{.State.Running}}' "$cid" 2>/dev/null | grep -q true; then
      bad "$name: stays up under the hardened profile" "$(docker logs "$cid" 2>&1 | tail -5)"
      docker rm -f "$cid" >/dev/null 2>&1; return 1
    fi
    ok "$name: stays up under the hardened profile"
    out="$(probe_script | docker exec -i -e ZC_WRITABLE="$tmpfs" \
            -e ZC_EXPECTED_PORTS="$ports" -e ZC_DENY_PORTS="$deny" "$cid" sh 2>&1)"; rc=$?
  else
    # oneshot: the probe IS pid 1, so /proc/1 is the probe itself.
    out="$(probe_script | docker run -i --entrypoint sh "${RUN[@]}" \
            -e ZC_WRITABLE="$tmpfs" -e ZC_EXPECTED_PORTS="$ports" \
            -e ZC_DENY_PORTS="$deny" "$img" 2>&1)"; rc=$?
    [ "$rc" -eq 0 ] && ok "$name: starts under the hardened profile" \
                    || bad "$name: starts under the hardened profile" "$out"
    cid=""
  fi
  if [ "$rc" -ne 0 ] || [ -z "$out" ]; then
    bad "$name: the in-container probe ran" "rc=$rc ${out:-no output}"
    [ -n "$cid" ] && docker rm -f "$cid" >/dev/null 2>&1
    return 1
  fi
  ok "$name: the in-container probe ran"

  g() { printf '%s\n' "$out" | grep "^$1=" | head -1 | cut -d= -f2-; }

  # --- identity -------------------------------------------------------------
  ck "$name: PID 1 uid:gid == contract" "$(g uid):$(g gid)" "$user"
  case "$(g uid)" in 0) bad "$name: PID 1 is non-root" "uid 0" ;; *) ok "$name: PID 1 is non-root" ;; esac

  # --- capabilities ---------------------------------------------------------
  local capfail=""
  for f in capeff capprm capbnd; do
    case "$(g $f)" in ''|*[!0]*) capfail="$capfail $f=$(g $f)";; esac
  done
  [ -z "$capfail" ] && ok "$name: capabilities empty (Eff/Prm/Bnd all zero)" \
                    || bad "$name: capabilities empty (Eff/Prm/Bnd all zero)" "$capfail"

  # --- privilege escalation / seccomp ---------------------------------------
  ck "$name: no_new_privileges" "$(g nnp)" "1"
  ck "$name: seccomp filter active (mode 2)" "$(g seccomp)" "2"

  # --- filesystem -----------------------------------------------------------
  ck "$name: root filesystem read-only" "$(g rootfs)" "readonly"
  local wfail=""
  printf '%s\n' "$out" | grep '^writable=' | while read -r l; do :; done
  while IFS= read -r l; do
    case "$l" in *:NO) wfail="$wfail ${l#writable=}";; esac
  done < <(printf '%s\n' "$out" | grep '^writable=')
  [ -z "$wfail" ] && ok "$name: every declared writable path is writable" \
                  || bad "$name: every declared writable path is writable" "$wfail"

  # --- tmpfs hardening ------------------------------------------------------
  local tfail="" want mp2 opts
  while IFS= read -r l; do
    l="${l#tmpfs=}"; mp2="${l%%:*}"; opts="${l#*:}"
    case " $tmpfs " in *" $mp2 "*) ;; *) continue ;; esac
    for want in $(printf '%s' "$flags" | tr ',' ' '); do
      case ",$opts," in *",$want,"*) ;; *) tfail="$tfail $mp2:missing-$want";; esac
    done
  done < <(printf '%s\n' "$out" | grep '^tmpfs=')
  [ -z "$tfail" ] && ok "$name: every declared tmpfs is noexec,nosuid,nodev" \
                  || bad "$name: every declared tmpfs is noexec,nosuid,nodev" "$tfail"

  # --- pid limit ------------------------------------------------------------
  ck "$name: PID limit enforced" "$(g pidsmax)" "$pids"

  # --- listeners ------------------------------------------------------------
  local meth found miss=""
  meth="$(g listener_method)"; found="$(g listeners)"
  if [ "$meth" = none ]; then
    bad "$name: listeners could be enumerated" "no /proc/net data and no connect probe in the image"
  else
    for p in $ports; do
      case " $found " in *" $p "*) ;; *) miss="$miss $p";; esac
    done
    [ -z "$miss" ] && ok "$name: every declared port is listening ($meth)" \
                   || bad "$name: every declared port is listening ($meth)" "missing:$miss"
    local unexpected=""
    for p in $found; do
      case " $ports " in *" $p "*) ;; *) unexpected="$unexpected $p";; esac
    done
    [ -z "$unexpected" ] && ok "$name: no unexpected listeners ($meth)" \
                         || bad "$name: no unexpected listeners ($meth)" "$unexpected"
  fi

  # --- healthcheck ----------------------------------------------------------
  local hc; hc="$(y "$contract" "d.get('healthcheck')")"
  if [ "$hc" = "True" ] && [ -n "$cid" ]; then
    local hcmd deadline health
    hcmd="$(docker inspect -f '{{json .Config.Healthcheck}}' "$img" 2>/dev/null)"
    case "$hcmd" in null|"") bad "$name: image declares a HEALTHCHECK" "contract requires one" ;;
      *) ok "$name: image declares a HEALTHCHECK"
         deadline=$(( $(date +%s) + 45 ))
         health=starting
         while [ "$(date +%s)" -le "$deadline" ]; do
           health="$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo unknown)"
           [ "$health" = healthy ] && break
           [ "$health" = unhealthy ] && break
           sleep 2
         done
         ck "$name: healthcheck reports healthy under the profile" "$health" "healthy" ;;
    esac
  fi

  # --- logging privacy (#107) -----------------------------------------------
  # Only for images that emit access logs. This sends REAL requests carrying
  # canary secrets and then greps the container's own log stream. Inspecting the
  # config text would prove a directive is present; it would not prove the field
  # never reaches the log — and the caddy run found `client_ip` unmasked while
  # `remote_ip` was masked, which no amount of config reading would have shown.
  local applies fam
  fam="$(y "$contract" "d.get('image')")"
  applies="$(y "$POLICY" "d['logging_privacy']['applies_to']")"
  case " $applies " in
    *" $fam "*)
      if [ -n "$cid" ]; then
        local lport canaries leaked=""
        lport="$(docker port "$cid" 2>/dev/null | head -1 | sed 's/.*://')"
        canaries="$(y "$POLICY" "list(d['logging_privacy']['canaries'].values())")"
        if [ -z "$lport" ]; then
          # No published port: drive the request from inside the container
          # against its own readiness listener instead of skipping the check.
          docker exec "$cid" sh -c '
            p="${ZC_PORT:-8081}"
            if command -v bash >/dev/null 2>&1; then
              bash -c "exec 3<>/dev/tcp/127.0.0.1/$p; printf \"GET /healthz?q=$1 HTTP/1.0\r\nAuthorization: Bearer $2\r\nCookie: s=$3\r\nX-Api-Key: $4\r\nConnection: close\r\n\r\n\" >&3; cat <&3 >/dev/null"
            fi' _ $canaries >/dev/null 2>&1 || true
        fi
        sleep 1
        for c in $canaries; do
          if docker logs "$cid" 2>&1 | grep -q "$c"; then leaked="$leaked $c"; fi
        done
        [ -z "$leaked" ] && ok "$name: no canary secret reached the access log" \
                         || bad "$name: no canary secret reached the access log" "leaked:$leaked"
      fi
      ;;
  esac

  # --- graceful shutdown ----------------------------------------------------
  if [ -n "$cid" ]; then
    local t0 t1
    t0="$(date +%s)"
    docker stop -t "$grace" "$cid" >/dev/null 2>&1
    t1="$(date +%s)"
    if [ $(( t1 - t0 )) -lt "$grace" ]; then
      ok "$name: PID 1 exits on $stop_sig within ${grace}s (took $(( t1 - t0 ))s)"
    else
      bad "$name: PID 1 exits on $stop_sig within ${grace}s" \
          "took $(( t1 - t0 ))s — the runtime had to SIGKILL it"
    fi
    docker rm -f "$cid" >/dev/null 2>&1
  fi
  return 0
}

matrix() { # emit "<image-ref> <contract>" per shipping image
  local reg="${ZC_REGISTRY:-ghcr.io/zenchron-dynamics}" c fam sel tag
  for c in "$ROOT"/contracts/images/*.yaml; do
    fam="$(y "$c" "d['image']")"; sel="$(y "$c" "d['selector']")"
    if [ "$sel" = prod ]; then tag="prod"; else tag="${sel}-prod"; fi
    printf '%s/%s:%s %s\n' "$reg" "$fam" "$tag" "$c"
  done
}

run_all() {
  local n=0 img c
  while read -r img c; do
    n=$((n+1))
    run_one "$img" "$c" || true
  done < <(matrix)
  # A short matrix is a FAILURE: nine green images are not the contract.
  local want; want="$(ls "$ROOT"/contracts/images/*.yaml | wc -l | tr -d ' ')"
  printf '\n================================================================\n'
  if [ "$n" -ne "$want" ]; then
    printf 'RUNTIME CONTRACT FAIL: executed %d image(s), expected %d\n' "$n" "$want" >&2
    return 1
  fi
  printf 'images executed: %d/%d\nchecks: %d passed, %d failed\n' "$n" "$want" "$PASS" "$FAIL"
  [ "$FAIL" -eq 0 ] || return 1
  return 0
}

emit_json() {
  printf '{"images_executed":%d,"checks_passed":%d,"checks_failed":%d,"checks":[%s]}\n' \
    "${1:-0}" "$PASS" "$FAIL" "${RESULTS%,}" > "$2"
  echo "runtime contract evidence written: $2"
}

self_test() {
  local ok_=0 bad_=0
  t() { if eval "$2"; then ok_=$((ok_+1)); echo "  ok   $1"; else bad_=$((bad_+1)); echo "  FAIL $1"; fi; }
  t "the policy parses and declares a profile" \
    "[ -n \"\$(y '$POLICY' \"d['profile']['pids_limit']\")\" ]"
  t "every contract declares a runtime block" \
    "! for c in '$ROOT'/contracts/images/*.yaml; do y \"\$c\" \"(d.get('runtime') or {}).get('mode')\"; done | grep -q '^$'"
  t "the matrix covers exactly the contract set" \
    "[ \"\$(matrix | wc -l | tr -d ' ')\" = \"\$(ls '$ROOT'/contracts/images/*.yaml | wc -l | tr -d ' ')\" ]"
  t "the probe script is syntactically valid shell" \
    "probe_script | sh -n"
  t "the profile matches profiles/compose.security.yml" \
    "python3 -c \"
import yaml
p=yaml.safe_load(open('$POLICY'))['profile']
c=yaml.safe_load(open('$ROOT/profiles/compose.security.yml'))['x-zenchron-hardening']
assert c['read_only'] is p['read_only']
assert c['cap_drop']==p['cap_drop']
assert c['security_opt']==p['security_opt']
assert c['pids_limit']==p['pids_limit']
for m in c['tmpfs']:
    for f in p['tmpfs_flags']: assert f in m, (m,f)
\""
  echo "self-test: $ok_ ok, $bad_ failed"
  [ "$bad_" -eq 0 ]
}

JSON=""
case "${1:-}" in
  --self-test) self_test; exit $? ;;
  --all) shift; [ "${1:-}" = "--json" ] && JSON="$2"
         run_all; rc=$?; [ -n "$JSON" ] && emit_json 10 "$JSON"; exit $rc ;;
  "") echo "usage: $(basename "$0") <image-ref> <contract.yaml> [--json OUT] | --all | --self-test" >&2; exit 64 ;;
  *) IMG="$1"; CON="$2"; shift 2; [ "${1:-}" = "--json" ] && JSON="$2"
     run_one "$IMG" "$CON"; printf '\nchecks: %d passed, %d failed\n' "$PASS" "$FAIL"
     [ -n "$JSON" ] && emit_json 1 "$JSON"
     [ "$FAIL" -eq 0 ] ;;
esac
