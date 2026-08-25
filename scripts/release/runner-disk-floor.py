#!/usr/bin/env python3
# =============================================================================
# scripts/release/runner-disk-floor.py — the free-disk floor for ONE runner kind.
# -----------------------------------------------------------------------------
# WHY THIS EXISTS AT ALL. policies/native-arch-requirements.yaml used to carry a
# single `required_runner.minimum_free_disk_gb: 60`. That number came from a
# self-hosted incident: the runner's own `_work`/`_update` self-update staging
# filled a PERSISTENT volume that survives every job. It was then treated as a
# property of the WORKLOAD, which it never was — it is a property of the runner's
# LIFECYCLE. An ephemeral hosted VM is destroyed after the job, has no staging
# carried over from previous jobs, and ships ~14 GB of free disk. Carrying 60 GB
# across would have made a runner that demonstrably runs the job look ineligible.
#
# So the floor is per-kind, and this is the one place that resolves it. Callers
# must name the kind they are; there is no default and no fallback to the largest
# number in the file, because a silent fallback is how the 60 spread in the first
# place.
#
# Usage:  runner-disk-floor.py <kind>        -> prints the integer GB floor
#         runner-disk-floor.py --self-test
# Exit:   0 resolved, 1 refused. An unknown or ambiguous kind is ALWAYS a refusal.
# =============================================================================
import os
import sys
import tempfile

import yaml

DEFAULT_POLICY = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..",
    "policies", "native-arch-requirements.yaml")


def refuse(msg):
    print("REFUSE: %s" % msg, file=sys.stderr)
    raise SystemExit(1)


def floor_for(kind, policy_path=None):
    """Resolve the free-disk floor, in GB, for exactly one runner kind."""
    path = policy_path or os.environ.get("POLICY") or DEFAULT_POLICY
    try:
        doc = yaml.safe_load(open(path))
    except Exception as exc:                      # unreadable policy is a refusal
        refuse("policy unreadable (%s): %s" % (path, exc))

    runners = (doc or {}).get("accepted_runners")
    if not isinstance(runners, list) or not runners:
        refuse("policy has no `accepted_runners` list — a single global disk "
               "floor cannot express a per-lifecycle requirement")

    kinds = [r.get("kind") for r in runners]
    if len(set(kinds)) != len(kinds):
        refuse("accepted_runners has duplicate `kind` values: %r" % kinds)

    match = [r for r in runners if r.get("kind") == kind]
    if not match:
        refuse("no accepted runner of kind %r; known kinds: %s"
               % (kind, ", ".join(sorted(str(k) for k in kinds))))
    if len(match) > 1:
        refuse("kind %r is ambiguous (%d entries)" % (kind, len(match)))

    val = match[0].get("minimum_free_disk_gb")
    if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
        refuse("minimum_free_disk_gb for kind %r is not a positive integer: %r"
               % (kind, val))
    return val


def _self_test():
    ok = fail = 0

    def t(label, fn):
        nonlocal ok, fail
        try:
            assert fn()
            print("  ok   %s" % label)
            ok += 1
        except BaseException as exc:              # SystemExit counts as a failure
            print("  FAIL %s (%r)" % (label, exc))
            fail += 1

    def refuses(fn):
        try:
            fn()
        except SystemExit:
            return True
        return False

    def write(doc):
        fd, p = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as fh:
            yaml.safe_dump(doc, fh)
        return p

    good = write({"accepted_runners": [
        {"kind": "ephemeral-hosted", "minimum_free_disk_gb": 9},
        {"kind": "persistent-self-hosted", "minimum_free_disk_gb": 60}]})
    t("resolves the floor for the kind asked for",
      lambda: floor_for("ephemeral-hosted", good) == 9)
    t("...and does NOT return the other kind's floor",
      lambda: floor_for("persistent-self-hosted", good) == 60)
    t("an unknown kind REFUSES rather than defaulting",
      lambda: refuses(lambda: floor_for("nope", good)))

    # NON-VACUITY: the shape this file exists to reject.
    flat = write({"required_runner": {"minimum_free_disk_gb": 60}})
    t("SABOTAGE: a single global floor is REFUSED, not silently reused",
      lambda: refuses(lambda: floor_for("ephemeral-hosted", flat)))

    dup = write({"accepted_runners": [
        {"kind": "ephemeral-hosted", "minimum_free_disk_gb": 9},
        {"kind": "ephemeral-hosted", "minimum_free_disk_gb": 60}]})
    t("SABOTAGE: a duplicated kind is REFUSED, never resolved to one of them",
      lambda: refuses(lambda: floor_for("ephemeral-hosted", dup)))

    bad = write({"accepted_runners": [
        {"kind": "ephemeral-hosted", "minimum_free_disk_gb": "lots"}]})
    t("a non-integer floor is REFUSED", lambda: refuses(lambda: floor_for("ephemeral-hosted", bad)))
    t("an unreadable policy is REFUSED",
      lambda: refuses(lambda: floor_for("ephemeral-hosted", "/nonexistent/policy.yaml")))

    # The real policy must answer for both kinds it ships.
    t("the real policy resolves the hosted kind", lambda: floor_for("ephemeral-hosted") > 0)
    t("the real policy resolves the self-hosted kind",
      lambda: floor_for("persistent-self-hosted") > 0)
    t("...and the two floors are NOT the same number",
      lambda: floor_for("ephemeral-hosted") != floor_for("persistent-self-hosted"))

    for p in (good, flat, dup, bad):
        os.unlink(p)
    print("self-test: %d ok, %d failed" % (ok, fail))
    return fail == 0


if __name__ == "__main__":
    arg = sys.argv[1] if len(sys.argv) > 1 else ""
    if arg == "--self-test":
        raise SystemExit(0 if _self_test() else 1)
    if not arg:
        print("usage: runner-disk-floor.py <kind> | --self-test", file=sys.stderr)
        raise SystemExit(2)
    print(floor_for(arg))
