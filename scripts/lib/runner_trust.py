#!/usr/bin/env python3
"""Runner trust-boundary checker for .github/workflows (issue #96).

A PARSER, not a text matcher. Review of the first implementation found two
security-boundary bypasses in the very guard meant to prevent workflow drift:

  R1  It only recognised ``pull_request_target:`` with a trailing colon, so the
      equally valid inline form ``on: [push, pull_request_target]`` passed the
      gate while being reachable through ``pull_request_target``.

  R2  It searched the whole pre-``steps:`` block for the trust predicate, so a
      job could satisfy the gate with the predicate under an unrelated key —
      ``env:``, ``name:``, ``concurrency:`` — while ``runs-on`` stayed
      unconditionally privileged:

          jobs:
            unsafe:
              runs-on: [self-hosted, linux, x64, zenchron]
              env:
                TRUST_NOTE: ${{ <predicate> }}
              steps:
                - run: ./attacker-controlled.sh

Both are fixed by reading the actual ``on:`` triggers, the actual ``runs-on``
value, and the actual job-level ``if:`` value.

Rules enforced (any violation exits non-zero):

  R1  no workflow may use ``pull_request_target``, in any trigger syntax;
  R2  every ``pull_request``-reachable job on a privileged label carries the
      predicate in its ``runs-on`` expression or its job-level ``if:``;
  R3  a ``pull_request``-reachable job may not delegate to another workflow;
  R4  discovery/parsing must never fail open.

Usage: runner_trust.py <workflows-dir> [--labels self-hosted,zenchron]
"""
from __future__ import annotations

import argparse
import glob
import os
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - environment problem, must fail closed
    print("FAIL: PyYAML is required to parse workflows", file=sys.stderr)
    sys.exit(1)

TRUST_EXPR = "github.event.pull_request.head.repo.full_name == github.repository"


def trigger_names(on) -> set[str]:
    """Every trigger name, whatever syntax was used.

    GitHub accepts a string, a list, or a mapping, and
    ``on: [push, pull_request_target]`` is exactly as reachable as
    ``pull_request_target:``. Treating only the mapping form as real was bypass
    R1.
    """
    if on is None:
        return set()
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on}
    return set()


def runs_on_parts(value) -> tuple[str, set[str]]:
    """Flatten ``runs-on`` to (text, label-set).

    Handles a plain string, a list of labels, and the
    ``{group: …, labels: [...]}`` mapping form.
    """
    if value is None:
        return "", set()
    if isinstance(value, str):
        return value, {value}
    if isinstance(value, list):
        return " ".join(str(v) for v in value), {str(v) for v in value}
    if isinstance(value, dict):
        parts: list[str] = []
        names: set[str] = set()
        for key in ("group", "labels"):
            v = value.get(key)
            if isinstance(v, list):
                parts += [str(x) for x in v]
                names |= {str(x) for x in v}
            elif v:
                parts.append(str(v))
                names.add(str(v))
        return " ".join(parts), names
    return str(value), {str(value)}


def check_dir(directory: str, labels: set[str]) -> int:
    files = sorted(glob.glob(os.path.join(directory, "*.yml")) +
                   glob.glob(os.path.join(directory, "*.yaml")))
    if not files:
        print("FAIL: no workflow files found under '%s' — gate would be vacuous" % directory,
              file=sys.stderr)
        return 1

    violations = 0
    for path in files:
        name = os.path.basename(path)
        try:
            doc = yaml.safe_load(open(path)) or {}
        except Exception as exc:
            print("VIOLATION [R4] %s: cannot parse as YAML: %s" % (name, exc), file=sys.stderr)
            violations += 1
            continue
        if not isinstance(doc, dict):
            print("VIOLATION [R4] %s: workflow is not a mapping" % name, file=sys.stderr)
            violations += 1
            continue

        # PyYAML resolves the bare key `on` to boolean True under YAML 1.1.
        on = doc.get("on", doc.get(True))
        triggers = trigger_names(on)

        if "pull_request_target" in triggers:
            print("VIOLATION [R1] %s: uses the 'pull_request_target' trigger" % name,
                  file=sys.stderr)
            violations += 1

        if not triggers & {"pull_request", "pull_request_target"}:
            continue

        jobs = doc.get("jobs")
        if not isinstance(jobs, dict) or not jobs:
            print("VIOLATION [R4] %s: pull_request-triggered but no jobs parsed" % name,
                  file=sys.stderr)
            violations += 1
            continue

        for job_id, job in jobs.items():
            if not isinstance(job, dict):
                print("VIOLATION [R4] %s:%s: job is not a mapping" % (name, job_id),
                      file=sys.stderr)
                violations += 1
                continue

            if "uses" in job:
                print("VIOLATION [R3] %s:%s: pull_request-reachable job calls another workflow; "
                      "runner trust is unprovable from this file" % (name, job_id),
                      file=sys.stderr)
                violations += 1
                continue

            if "runs-on" not in job:
                print("VIOLATION [R4] %s:%s: no runs-on; cannot prove runner trust"
                      % (name, job_id), file=sys.stderr)
                violations += 1
                continue

            text, label_set = runs_on_parts(job.get("runs-on"))
            if not (labels & label_set or any(l in text for l in labels)):
                continue  # GitHub-hosted: nothing to guard

            # The predicate must be in the ACTUAL runs-on expression or the
            # ACTUAL job-level `if:`. Anywhere else gates nothing — that was
            # bypass R2.
            job_if = job.get("if")
            job_if = "" if job_if is None else str(job_if)
            if TRUST_EXPR in text or TRUST_EXPR in job_if:
                continue

            print("VIOLATION [R2] %s:%s: privileged runner on a pull_request-reachable job "
                  "without the same-repo trust guard" % (name, job_id), file=sys.stderr)
            print("               expected '%s' in runs-on or a job-level if:" % TRUST_EXPR,
                  file=sys.stderr)
            violations += 1

    if violations:
        print("RESULT: FAIL (%d runner-trust violation(s) across %d workflow(s))"
              % (violations, len(files)), file=sys.stderr)
        return 1
    print("RESULT: PASS (%d workflow(s); no fork PR can reach a privileged runner)" % len(files))
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("directory")
    ap.add_argument("--labels", default="self-hosted,zenchron")
    args = ap.parse_args()
    labels = {l.strip() for l in args.labels.split(",") if l.strip()}
    return check_dir(args.directory, labels)


if __name__ == "__main__":
    sys.exit(main())
