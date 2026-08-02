"""Stable, unique identity for a vulnerability-ledger record.

THE single implementation. Three tools pair records by this string —
scripts/validate-vulnerability-exceptions.sh (duplicate detection),
scripts/reconcile-vulnerabilities.sh (which record governed a finding) and
scripts/ci/assert-no-stale-exceptions.sh (which records matched nothing) — and
if any of them computed it differently, records would silently stop matching and
live exceptions would be reported as stale.

`cve@image` was not unique: two records for the same advisory and image scoped
to different packages, or to different installed versions, collapsed to one key.
The validator then rejected a legitimate pair as duplicates, and the aggregate
could never report either of them stale.
"""

# The fields that, together, define one acceptance scope. Adding a field here
# makes previously-identical records distinct; removing one merges them.
ID_FIELDS = ("cve", "image", "package", "installed_version")


def _part(value):
    if value is None:
        return "*"
    if isinstance(value, (list, tuple)):
        # `package` may be the SET of binary packages built from one source
        # package. Sort so declaration order cannot change identity.
        return ",".join(sorted(str(x) for x in value))
    return str(value)


def exc_id(record):
    """Return the stable id of one ledger record (a mapping)."""
    return "|".join(_part(record.get(f)) for f in ID_FIELDS)


def duplicate_scopes(records):
    """Return [(first_index, dup_index, id)] for records sharing a scope.

    Two records with an identical scope are indistinguishable: the first
    governs every matching finding and the second can never match, so it would
    be reported stale forever and could not be cleared by any scan.
    """
    seen, dups = {}, []
    for i, r in enumerate(records):
        key = exc_id(r)
        if key in seen:
            dups.append((seen[key], i, key))
        else:
            seen[key] = i
    return dups


def _self_test():
    assert exc_id({"cve": "CVE-1", "image": "nginx"}) == "CVE-1|nginx|*|*"
    # The collision the old cve@image key produced.
    a = {"cve": "CVE-1", "image": "nginx", "package": "libfoo"}
    b = {"cve": "CVE-1", "image": "nginx", "package": "libbar"}
    assert exc_id(a) != exc_id(b), "same cve+image, different package must differ"
    c = {"cve": "CVE-1", "image": "nginx", "package": "libfoo",
         "installed_version": "1.0"}
    d = {"cve": "CVE-1", "image": "nginx", "package": "libfoo",
         "installed_version": "2.0"}
    assert exc_id(c) != exc_id(d), "different installed_version must differ"
    # Package sets are order-independent.
    assert (exc_id({"cve": "C", "image": "i", "package": ["b", "a"]})
            == exc_id({"cve": "C", "image": "i", "package": ["a", "b"]}))
    # A missing field is not the same as an empty one.
    assert exc_id({"cve": "C", "image": "i"}) != exc_id(
        {"cve": "C", "image": "i", "package": ""})
    assert duplicate_scopes([a, b]) == []
    assert duplicate_scopes([a, dict(a)]) == [(0, 1, exc_id(a))]
    assert duplicate_scopes([]) == []
    print("exception_id.py: SELF-TEST OK (8 assertions)")


if __name__ == "__main__":
    _self_test()
