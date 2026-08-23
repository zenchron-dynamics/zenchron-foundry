#!/usr/bin/env python3
"""Fixture PHP version lists must agree with the live MATRIX_IMAGES.

A literal like `for v in ("8.3","8.4")` is not wrong in itself — it is wrong when
it disagrees with the matrix it stands in for. The earlier check matched that
literal unconditionally, so it was correct while PHP 8.5 was in the matrix and
became a false positive the moment 8.5 was withdrawn. Comparing against the
matrix makes it correct in both directions.
"""
import glob, re, subprocess, sys

out = subprocess.run(["bash", "-c", ". scripts/lib/common.sh; echo $MATRIX_IMAGES"],
                     capture_output=True, text=True).stdout.split()
live = sorted({t.split(":")[1] for t in out if t.startswith("php-")})
if not live:
    print("REFUSE: no PHP versions found in MATRIX_IMAGES — the check would be vacuous")
    sys.exit(1)

bad = []
for f in glob.glob("scripts/**/*.sh", recursive=True) + glob.glob("tests/**/*.sh", recursive=True):
    try:
        text = open(f).read()
    except OSError:
        continue
    for m in re.finditer(r"for v in \(([^)]*)\)", text):
        vs = sorted(set(re.findall(r'"([0-9]+\.[0-9]+)"', m.group(1))))
        if vs and vs != live:
            bad.append((f, vs))

if bad:
    print("REFUSE: PHP version fixture lists disagree with MATRIX_IMAGES %r" % live)
    for f, vs in bad:
        print("  %s: %r" % (f, vs))
    sys.exit(1)
print("fixture PHP versions agree with the matrix: %r" % live)
