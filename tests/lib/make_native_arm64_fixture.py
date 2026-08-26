#!/usr/bin/env python3
# =============================================================================
# tests/lib/make_native_arm64_fixture.py
# -----------------------------------------------------------------------------
# TEST FIXTURE ONLY. THIS DOES NOT MAKE ANY EVIDENCE NATIVE.
#
# It takes an acceptance-evidence record whose linux/arm64 children ran under
# QEMU and returns a COPY in which they are recorded as having run natively, so
# that the offline self-tests can exercise the seal's HAPPY path under
# policies/native-arch-requirements.yaml `release_gate.require_native_arm64:
# true`.
#
# WHY THIS EXISTS AT ALL. The only committed multi-architecture acceptance
# record — docs/audits/acceptance-multiarch-2026-08-20/acceptance-evidence.json —
# is emulated, and says so. Once the seal REQUIRES native arm64 evidence, that
# record can no longer be sealed as a release. That is the correct outcome and
# it is asserted directly. But every OTHER seal refusal (R1, R4, R5, R6, R7, R8,
# R11, R12, R13) needs a bundle that would otherwise seal, or those assertions
# start passing for the native-architecture reason instead of their own — which
# is exactly the "passed for the wrong reason" failure this suite keeps removing.
#
# WHY IT LIVES UNDER tests/ AND NOT UNDER scripts/. A tool in scripts/ that
# rewrites emulated evidence into native evidence is not a fixture generator, it
# is a laundering step for the one claim #111 exists to protect. Nothing under
# scripts/ may call this outside its own --self-test, its output is never written
# into docs/audits/, and every record it emits is stamped `fixture: true` and
# carries a statement saying so.
#
# Usage:
#   make_native_arm64_fixture.py <acceptance.json> <out.json> [--platform linux/arm64]
# =============================================================================
import argparse
import json
import sys

FIXTURE_NOTE = (
    "FIXTURE — synthesised by tests/lib/make_native_arm64_fixture.py from an "
    "emulated acceptance record so that offline self-tests can exercise a "
    "sealable bundle under a mandatory native-architecture policy. This is NOT "
    "audit evidence and NOTHING in it was executed natively."
)


def main(argv):
    ap = argparse.ArgumentParser()
    ap.add_argument("evidence")
    ap.add_argument("out")
    ap.add_argument("--platform", default="linux/arm64")
    a = ap.parse_args(argv)

    ev = json.load(open(a.evidence))
    arch = a.platform.rsplit("/", 1)[-1]

    touched = 0
    for c in ev.get("children") or []:
        if c.get("platform") != a.platform:
            continue
        c["execution_mode"] = "native"
        c["host_architecture"] = arch
        c["runner_name"] = "fixture-hosted-%s" % arch
        touched += 1
    if not touched:
        print("REFUSE: no %s children to rewrite — a fixture that changes nothing "
              "would silently assert nothing" % a.platform, file=sys.stderr)
        return 1

    disc = ev.setdefault("execution_disclosure", {})
    disc["native_children"] = len(ev["children"])
    disc["qemu_children"] = 0
    disc["statement"] = FIXTURE_NOTE
    ev["fixture"] = True
    ev["fixture_note"] = FIXTURE_NOTE

    with open(a.out, "w") as fh:
        json.dump(ev, fh, indent=2)
        fh.write("\n")
    print("native fixture: %d %s child(ren) rewritten" % (touched, a.platform))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
