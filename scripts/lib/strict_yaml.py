"""YAML loading that REFUSES duplicate mapping keys.

`yaml.safe_load` accepts duplicates silently and keeps the last one. In a
security ledger that is a bypass, not a style problem: a record written as

    release_blocking: true
    release_blocking: false
    verified_architectures: [linux/amd64]
    verified_architectures: [linux/amd64, linux/arm64]

reads to a human as blocking and amd64-only, while every tool enforces
non-blocking and amd64+arm64 — quietly authorising the architecture the
publication gate exists to refuse. The same trick hides an expiry, an owner, or
a second `exceptions:` key that replaces the whole list.

THE single strict loader. Every consumer of policies/vulnerability-exceptions.yaml
uses it, so no consumer can be the lenient one.
"""

import yaml


class DuplicateKeyError(ValueError):
    """Raised when a mapping declares the same key twice."""


class _StrictLoader(yaml.SafeLoader):
    pass


def _no_duplicates(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            mark = key_node.start_mark
            raise DuplicateKeyError(
                "duplicate key %r at line %d, column %d — YAML keeps only the "
                "LAST value, so the file does not mean what it appears to mean"
                % (key, mark.line + 1, mark.column + 1))
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _no_duplicates)


def load(stream_or_path):
    """Parse YAML, raising DuplicateKeyError on any duplicated mapping key."""
    if hasattr(stream_or_path, "read"):
        return yaml.load(stream_or_path, Loader=_StrictLoader)
    with open(stream_or_path) as fh:
        return yaml.load(fh, Loader=_StrictLoader)


def _self_test():
    # A clean document still loads.
    assert load_str("a: 1\nb: 2\n") == {"a": 1, "b": 2}

    # The security-relevant shapes.
    for src, why in [
        ("exceptions:\n  - cve: C\n    release_blocking: true\n"
         "    release_blocking: false\n", "duplicate security field"),
        ("exceptions:\n  - cve: C\n    verified_architectures: [linux/amd64]\n"
         "    verified_architectures: [linux/amd64, linux/arm64]\n",
         "duplicate architecture list"),
        ("exceptions: []\nexceptions:\n  - cve: C\n", "duplicate top-level key"),
        ("not_affected: []\nnot_affected: []\n", "duplicate not_affected"),
        ("a:\n  b:\n    c: 1\n    c: 2\n", "duplicate nested key"),
    ]:
        try:
            load_str(src)
        except DuplicateKeyError:
            pass
        else:
            raise AssertionError("accepted a %s" % why)

    # Duplicates inside a sequence of mappings are still caught.
    try:
        load_str("l:\n  - {x: 1}\n  - {y: 1, y: 2}\n")
    except DuplicateKeyError:
        pass
    else:
        raise AssertionError("accepted a duplicate inside a sequence")

    # Repeating a key in DIFFERENT mappings is legitimate.
    assert load_str("l:\n  - {x: 1}\n  - {x: 2}\n") == {"l": [{"x": 1}, {"x": 2}]}

    # yaml.safe_load would have accepted the first case — proving this is not a
    # no-op wrapper.
    assert yaml.safe_load("a: 1\na: 2\n") == {"a": 2}

    print("strict_yaml.py: SELF-TEST OK (9 assertions)")


def load_str(text):
    return yaml.load(text, Loader=_StrictLoader)


if __name__ == "__main__":
    _self_test()
