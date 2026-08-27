#!/usr/bin/env python3
"""Buildless upstream monitor — evaluation and expiry checkpoints.

OBSERVE AND REPORT. This program builds nothing, pulls no pin forward, renews
no exception, removes no record and writes no file under policies/. It reads
policies/upstream-watch.yaml, reads policies/vulnerability-exceptions.yaml,
reads an observation document produced by scripts/upstream-monitor.sh, and
prints a verdict. Every write path this repository has is somewhere else.

  evaluate     compare an observation against the watch config + ledger
  checkpoints  render the expiry operating checkpoints for a given date
  --self-test  run the offline unit checks

WHY THE ALERT RULE IS SO NARROW
-------------------------------
A monitor that fires on tag movement is worse than no monitor: it trains the
maintainer to dismiss it, and it is wrong. Measured precedent in this repo —
the FrankenPHP 8.3 INDEX digest moved while both platform manifests were
byte-identical, and when 8.4 moved on BOTH platforms the embedded modules were
unchanged. Three separate observations are therefore kept apart:

    index_moved      the manifest-list digest changed
    platform_moved   a linux/<arch> manifest digest changed
    content_changed  a watched component's version inside the artifact changed

Only the third can bear on remediation, and even then only when the new version
reaches the declared clearing floor on EVERY required platform. The first two
are recorded as notes and can never, on their own, produce an alert. That is
asserted by tests/vulnerability-policy/test_upstream_monitor.sh, which replays
both real movements and requires silence.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))

from exception_id import exc_id  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WATCH = os.path.join(REPO, "policies", "upstream-watch.yaml")
LEDGER = os.path.join(REPO, "policies", "vulnerability-exceptions.yaml")

# Alert classes. There are exactly two, and neither is reachable from digest
# movement alone.
ALERT_EXIT_MET = "exit-condition-met"
ALERT_CONTRADICTED = "ledger-contradicted"


# --- version comparison ------------------------------------------------------
# Deliberately conservative. An ordering the comparator is not sure about
# returns None, and None NEVER satisfies a clearing floor — an unsure monitor
# stays silent and says so, rather than announcing a remediation that is not
# there.

def _split_num(text):
    """Split a dotted numeric run into ints, stopping at the first non-numeric."""
    out = []
    for part in text.split("."):
        digits = ""
        for ch in part:
            if ch.isdigit():
                digits += ch
            else:
                break
        if digits == "":
            return out, False
        out.append(int(digits))
        if digits != part:
            # Trailing non-numeric (a pre-release suffix, an epoch marker...).
            return out, False
    return out, True


def _cmp_seq(a, b):
    for x, y in zip(a, b):
        if x != y:
            return -1 if x < y else 1
    if len(a) != len(b):
        return -1 if len(a) < len(b) else 1
    return 0


def cmp_version(ecosystem, left, right):
    """Return -1/0/1 for left vs right, or None when the order is not certain."""
    if left is None or right is None:
        return None
    left, right = str(left).strip(), str(right).strip()
    if left == right:
        return 0

    if ecosystem == "gomod":
        lv, rv = left.lstrip("vV"), right.lstrip("vV")
        # A pre-release ("v1.2.3-rc1") is not ordered here; refuse rather than
        # guess, because guessing high would fake a cleared exit condition.
        if "-" in lv or "-" in rv or "+" in lv or "+" in rv:
            return None
        a, ok_a = _split_num(lv)
        b, ok_b = _split_num(rv)
        return _cmp_seq(a, b) if (ok_a and ok_b) else None

    if ecosystem == "apk":
        # Alpine: <upstream>-r<pkgrel>. Both halves are compared numerically.
        if "-r" not in left or "-r" not in right:
            return None
        lu, _, lr = left.rpartition("-r")
        ru, _, rr = right.rpartition("-r")
        a, ok_a = _split_num(lu)
        b, ok_b = _split_num(ru)
        if not (ok_a and ok_b) or not (lr.isdigit() and rr.isdigit()):
            return None
        c = _cmp_seq(a, b)
        if c != 0:
            return c
        return -1 if int(lr) < int(rr) else (1 if int(lr) > int(rr) else 0)

    # Debian versions carry epochs, tildes and +debNuM revisions whose ordering
    # is dpkg's, not ours. We never compare them: the Debian watch is a
    # fix-EXISTENCE observation, which needs no ordering at all.
    return None


def satisfies(ecosystem, observed, floor):
    """True only when `observed` is provably at or above `floor`."""
    c = cmp_version(ecosystem, observed, floor)
    return c is not None and c >= 0


# --- loading -----------------------------------------------------------------

def _load_yaml(path):
    import yaml
    with open(path, encoding="utf-8") as fh:
        return yaml.safe_load(fh)


def load_ledger(path=None):
    doc = _load_yaml(path or LEDGER)
    return {exc_id(r): r for r in doc.get("exceptions", [])}


# --- config/ledger binding ---------------------------------------------------

def bind_groups(watch, ledger):
    """Every declared record must exist; every fail-closed record must be declared.

    Both directions matter. The first catches a group that quietly stopped
    describing anything real. The second catches a record added to the
    fail-closed cohort that no checkpoint would ever name — a record nobody is
    reminded about is the failure this whole lane exists to prevent.
    """
    problems = []
    declared = []
    for gid, g in sorted((watch.get("groups") or {}).items()):
        for rid in g.get("records") or []:
            declared.append(rid)
            if rid not in ledger:
                problems.append(
                    "group %s names a record that is not in the ledger: %s" % (gid, rid))
    dupes = sorted({r for r in declared if declared.count(r) > 1})
    for r in dupes:
        problems.append("record declared in more than one group: %s" % r)

    fail_closed = str(watch["expiry_controls"]["fail_closed"])
    cohort = [rid for rid, rec in ledger.items()
              if str(rec.get("expires_at")) == fail_closed]
    for rid in sorted(cohort):
        if rid not in declared:
            problems.append(
                "ledger record expires at the fail-closed date %s but no group "
                "names it, so no checkpoint would report it: %s" % (fail_closed, rid))
    return sorted(cohort), problems


# --- evaluation --------------------------------------------------------------

def evaluate(watch, ledger, observation):
    """Compare one observation document against the watch config and ledger."""
    report = {
        "schema_version": 1,
        "record_type": "upstream-monitor-verdict",
        "evidence_class": "upstream-base",
        "evidence_class_note": (
            "An upstream-base observation establishes upstream ownership and "
            "patched-artifact availability ONLY. It is never read as a Foundry "
            "child's package inventory."),
        "observed_at": observation.get("observed_at"),
        "watch_config_sha256": observation.get("watch_config_sha256"),
        "ledger_sha256": observation.get("ledger_sha256"),
        "binds": [],
        "notes": [],
        "alerts": [],
        "gaps": [],
    }

    _cohort, problems = bind_groups(watch, ledger)
    for p in problems:
        report["alerts"].append({
            "class": ALERT_CONTRADICTED,
            "subject": "watch-config/ledger binding",
            "detail": p,
            "groups": [],
            "records": [],
        })

    by_id = {a["id"]: a for a in watch.get("artifacts") or []}
    seen = set()

    for art_obs in observation.get("artifacts") or []:
        aid = art_obs.get("id")
        art = by_id.get(aid)
        if art is None:
            report["gaps"].append("observation names an artifact absent from the watch config: %s" % aid)
            continue
        seen.add(aid)
        report["binds"].append(_evaluate_artifact(art, art_obs, watch, ledger, report))

    for aid in sorted(set(by_id) - seen):
        report["gaps"].append(
            "watched artifact was not observed on this run (no evidence either "
            "way; this is NOT a clean result): %s" % aid)

    report["alert_count"] = len(report["alerts"])
    report["verdict"] = "ALERT" if report["alerts"] else "QUIET"
    return report


def _evaluate_artifact(art, obs, watch, ledger, report):
    """Build the artifact bind record and append any alerts/notes it justifies."""
    aid = art["id"]
    base = art.get("baseline") or {}
    base_platforms = base.get("platforms") or {}
    obs_platforms = obs.get("platforms") or {}
    required = list(art.get("required_platforms") or [])

    index_moved = bool(obs.get("index_digest")) and obs.get("index_digest") != base.get("index_digest")
    moved_platforms = [p for p in sorted(obs_platforms)
                       if base_platforms.get(p) and obs_platforms[p].get("manifest_digest") != base_platforms.get(p)]

    bind = {
        "artifact": aid,
        "tag": art["tag"],
        "retrieved_at_utc": obs.get("observed_at"),
        "index_digest": obs.get("index_digest"),
        "baseline_index_digest": base.get("index_digest"),
        "index_moved": index_moved,
        "required_platforms": required,
        "platforms": {},
        "components": [],
        "movement_class": "unchanged",
    }
    for p in required:
        po = obs_platforms.get(p) or {}
        bind["platforms"][p] = {
            "platform_digest": po.get("manifest_digest"),
            "baseline_platform_digest": base_platforms.get(p),
            "platform_moved": p in moved_platforms,
            "inventory_source": po.get("inventory_source"),
            "inventory_size": len(po.get("inventory") or {}),
        }

    # --- the three-way movement classification, stated once and reused --------
    content_changed = False
    for spec in art.get("components") or []:
        name = spec["component"]
        eco = spec.get("ecosystem", "gomod")
        floor = spec.get("clearing_version")
        baseline_version = spec.get("baseline_version")
        expect_absent = bool(spec.get("expect_absent"))
        groups = list(spec.get("groups") or [])

        per_platform = {}
        observed_any_inventory = False
        for p in required:
            po = obs_platforms.get(p) or {}
            inv = po.get("inventory")
            if inv is None:
                per_platform[p] = None
                continue
            observed_any_inventory = True
            per_platform[p] = inv.get(name)

        entry = {
            "component": name,
            "ecosystem": eco,
            "baseline_version": baseline_version,
            "clearing_version": floor,
            "expect_absent": expect_absent,
            "observed": per_platform,
            "groups": groups,
            "records": _records_for(watch, groups),
            "clears": False,
        }

        if not observed_any_inventory:
            entry["state"] = "not-observed"
            report["gaps"].append(
                "%s: no package/module inventory was retrieved for %s on any "
                "required platform; nothing is concluded about it" % (aid, name))
            bind["components"].append(entry)
            continue

        if expect_absent:
            present = {p: v for p, v in per_platform.items() if v}
            if present:
                entry["state"] = "unexpectedly-present"
                # The ledger records for this group attribute the package to
                # this artifact. Measurement said it was absent. If it appears,
                # the attribution question changes and the maintainer must know.
                report["alerts"].append({
                    "class": ALERT_CONTRADICTED,
                    "subject": "%s %s" % (aid, name),
                    "detail": (
                        "the watch config records %s as ABSENT from %s (the "
                        "package enters the child through the Foundry layer, "
                        "not the base). It is now present at %s. The ledger's "
                        "source attribution for this group depends on that."
                        % (name, art["tag"], json.dumps(present, sort_keys=True))),
                    "groups": groups,
                    "records": entry["records"],
                })
            else:
                entry["state"] = "absent-as-recorded"
            bind["components"].append(entry)
            continue

        changed = [p for p, v in per_platform.items()
                   if v is not None and baseline_version is not None and v != baseline_version]
        if changed:
            content_changed = True

        # CLEARING REQUIRES EVERY REQUIRED PLATFORM. A component fixed on amd64
        # and not arm64 clears nothing: the cohort is both children, and the
        # exit conditions say "on both required platforms".
        clears = bool(floor) and all(
            satisfies(eco, per_platform.get(p), floor) for p in required)
        entry["clears"] = clears

        if clears:
            entry["state"] = "clearing-version-reached"
            report["alerts"].append({
                "class": ALERT_EXIT_MET,
                "subject": "%s %s" % (aid, name),
                "detail": (
                    "a consumable official artifact now embeds %s at %s on every "
                    "required platform, at or above the clearing floor %s. This "
                    "REPORTS that an existing exit condition appears satisfied. "
                    "It moves no pin, rebuilds nothing and renews nothing; the "
                    "maintainer role decides what happens next."
                    % (name,
                       json.dumps({p: per_platform.get(p) for p in required}, sort_keys=True),
                       floor)),
                "groups": groups,
                "records": entry["records"],
            })
        elif changed:
            entry["state"] = "moved-below-clearing-version"
            report["notes"].append(
                "%s: %s moved %s -> %s but the clearing floor is %s. NOT "
                "remediation; no exit condition is satisfied."
                % (aid, name, baseline_version,
                   json.dumps({p: per_platform.get(p) for p in changed}, sort_keys=True), floor))
        else:
            entry["state"] = "unchanged-at-baseline"

        bind["components"].append(entry)

    if content_changed:
        bind["movement_class"] = "content-change"
    elif moved_platforms:
        bind["movement_class"] = "platform-manifest-movement"
    elif index_moved:
        bind["movement_class"] = "index-movement-only"

    if bind["movement_class"] == "index-movement-only":
        report["notes"].append(
            "%s: the INDEX digest moved (%s -> %s) while every required platform "
            "manifest is byte-identical. The Linux artifact did not change. This "
            "is not remediation and is not an alert."
            % (aid, base.get("index_digest"), obs.get("index_digest")))
    elif bind["movement_class"] == "platform-manifest-movement":
        report["notes"].append(
            "%s: platform manifests moved (%s) but every watched component is at "
            "its recorded baseline version. A different artifact carrying the "
            "same vulnerable components is not remediation and is not an alert."
            % (aid, ", ".join(moved_platforms)))

    return bind


def _records_for(watch, groups):
    out = []
    for gid in groups:
        out.extend((watch.get("groups") or {}).get(gid, {}).get("records") or [])
    return sorted(set(out))


# --- Debian / Alpine remediation-state evaluation ----------------------------

def evaluate_distro(watch, observation, report):
    """A published distro fix contradicts a `fix_available: false` claim.

    It does NOT satisfy an image exit condition: a fixed source package existing
    in bookworm-security puts it in no image. That distinction is the whole
    reason this is a separate function with a separate alert class.
    """
    obs = observation.get("debian") or {}
    for spec in (watch.get("debian_watch") or {}).get("source_packages") or []:
        src = spec["source"]
        state = obs.get(src)
        if state is None:
            report["gaps"].append(
                "Debian remediation state for source package '%s' was not "
                "retrieved; nothing is concluded about it" % src)
            continue
        for adv in spec.get("advisories") or []:
            fixed = (state.get("fixed") or {}).get(adv)
            if fixed and spec.get("ledger_fix_available") is False:
                report["alerts"].append({
                    "class": ALERT_CONTRADICTED,
                    "subject": "debian/%s %s" % (src, adv),
                    "detail": (
                        "the ledger records fix_available: false for this "
                        "advisory, and Debian now publishes a fixed %s at %s in "
                        "%s. The record's own claim about upstream is no longer "
                        "true. This is a contradiction to resolve, not a "
                        "remediation: a fixed source package is in no image "
                        "until an official base ships it."
                        % (src, fixed, state.get("suite", "bookworm-security"))),
                    "groups": list(spec.get("groups") or []),
                    "records": _records_for(watch, spec.get("groups") or []),
                })
    # Alpine availability is recorded, never alerted on by itself: the caddy
    # image performs no package resolution at build time (ADR-0001), so an
    # available aport cannot reach it except through an official rebuild, which
    # the `artifacts` watch already covers.
    for spec in (watch.get("alpine_watch") or {}).get("packages") or []:
        avail = (observation.get("alpine") or {}).get(spec["package"])
        if avail is None:
            report["gaps"].append(
                "Alpine availability for '%s' was not retrieved" % spec["package"])
        else:
            report["notes"].append(
                "alpine %s: branch head %s (fixed aport for this cohort is %s). "
                "Availability is not remediation — no Foundry build resolves "
                "Alpine packages." % (spec["package"], avail, spec.get("fixed_version")))
    return report


# --- expiry operating checkpoints --------------------------------------------

CHECKPOINT_PREAMBLE = (
    "This is a PROMPT TO DECIDE. It schedules nothing, renews nothing and "
    "extends nothing. No tool in this repository may write "
    "policies/vulnerability-exceptions.yaml; continuing any record below is a "
    "fresh risk acceptance the maintainer role records by hand, with its own "
    "justification. If nothing is recorded, the records expire as written."
)


def checkpoints(watch, ledger, today, window_days=45):
    ec = watch["expiry_controls"]
    fail_closed = str(ec["fail_closed"])
    cohort, problems = bind_groups(watch, ledger)
    t = _dt.date.fromisoformat(today)
    fc = _dt.date.fromisoformat(fail_closed)

    out = {
        "schema_version": 1,
        "record_type": "expiry-checkpoint-report",
        "today": today,
        "fail_closed": fail_closed,
        "days_to_fail_closed": (fc - t).days,
        "renewal_is_not_automatic": ec["renewal_is_not_automatic"].strip(),
        "fail_closed_effect": ec["fail_closed_effect"].strip(),
        "preamble": CHECKPOINT_PREAMBLE,
        "record_count": len(cohort),
        "binding_problems": problems,
        "due": [],
        "upcoming": [],
        "groups": [],
    }

    for cp in ec.get("checkpoints") or []:
        d = _dt.date.fromisoformat(str(cp["date"]))
        item = {
            "id": cp["id"],
            "date": str(cp["date"]),
            "title": cp["title"],
            "prompt": " ".join(cp["prompt"].split()),
            "days_from_today": (d - t).days,
        }
        if d <= t:
            out["due"].append(item)
        elif (d - t).days <= window_days:
            out["upcoming"].append(item)

    for gid, g in sorted((watch.get("groups") or {}).items()):
        recs = [r for r in (g.get("records") or []) if r in ledger]
        out["groups"].append({
            "group": gid,
            "title": g["title"],
            "selector": g["selector"],
            "exit_condition": " ".join(g["exit_condition"].split()),
            "record_count": len(recs),
            "records": [{
                "id": r,
                "cve": ledger[r].get("cve"),
                "image": ledger[r].get("image"),
                "package": ledger[r].get("package"),
                "installed_version": ledger[r].get("installed_version"),
                "expires_at": str(ledger[r].get("expires_at")),
            } for r in recs],
        })

    out["active"] = bool(out["due"]) or bool(out["upcoming"])
    return out


def render_checkpoints(rep):
    lines = []
    if not rep["active"]:
        lines.append("expiry checkpoints: none due or within the reporting window "
                     "(today %s, fail-closed %s)." % (rep["today"], rep["fail_closed"]))
        return "\n".join(lines)

    lines.append("EXPIRY CHECKPOINT — %d record(s) in %d group(s) expire %s"
                 % (rep["record_count"], len(rep["groups"]), rep["fail_closed"]))
    lines.append("today %s — %d day(s) to the fail-closed date"
                 % (rep["today"], rep["days_to_fail_closed"]))
    lines.append("")
    lines.append(rep["preamble"])
    lines.append("")
    lines.append("ON %s: %s" % (rep["fail_closed"], rep["fail_closed_effect"]))
    lines.append("")
    lines.append(rep["renewal_is_not_automatic"])
    lines.append("")
    for k, label in (("due", "DUE"), ("upcoming", "UPCOMING")):
        for cp in rep[k]:
            lines.append("[%s] %s — %s (%+d day(s))"
                         % (label, cp["date"], cp["title"], cp["days_from_today"]))
            lines.append("    %s" % cp["prompt"])
    lines.append("")
    lines.append("GROUPS AND RECORDS AT STAKE (a date alone is not actionable):")
    for g in rep["groups"]:
        lines.append("")
        lines.append("  %s  %s" % (g["group"], g["title"]))
        lines.append("     selector: %s   records: %d" % (g["selector"], g["record_count"]))
        lines.append("     exit condition: %s" % g["exit_condition"])
        for r in g["records"]:
            pkg = r["package"]
            pkg = ",".join(pkg) if isinstance(pkg, list) else pkg
            lines.append("       - %s  %s  %s @ %s  (expires %s)"
                         % (r["cve"], r["image"], pkg, r["installed_version"], r["expires_at"]))
    if rep["binding_problems"]:
        lines.append("")
        lines.append("BINDING PROBLEMS — the report above may be incomplete:")
        for p in rep["binding_problems"]:
            lines.append("  - %s" % p)
    return "\n".join(lines)


def render_verdict(rep):
    lines = []
    for b in rep["binds"]:
        lines.append("bind %s (%s)" % (b["artifact"], b["tag"]))
        lines.append("  retrieved %s   movement: %s" % (b["retrieved_at_utc"], b["movement_class"]))
        lines.append("  index %s (baseline %s, moved=%s)"
                     % (b["index_digest"], b["baseline_index_digest"], b["index_moved"]))
        for p, pv in sorted(b["platforms"].items()):
            lines.append("  %-14s %s (baseline %s, moved=%s, %d inventory entries)"
                         % (p, pv["platform_digest"], pv["baseline_platform_digest"],
                            pv["platform_moved"], pv["inventory_size"]))
        for c in b["components"]:
            lines.append("    %-32s %-8s %s"
                         % (c["component"], c["ecosystem"], c["state"]))
    for n in rep["notes"]:
        lines.append("note: %s" % n)
    for g in rep["gaps"]:
        lines.append("gap:  %s" % g)
    if rep["alerts"]:
        lines.append("")
        for a in rep["alerts"]:
            lines.append("ALERT [%s] %s" % (a["class"], a["subject"]))
            lines.append("  %s" % a["detail"])
            if a["groups"]:
                lines.append("  groups:  %s" % ", ".join(a["groups"]))
            for r in a["records"]:
                lines.append("  record:  %s" % r)
        lines.append("")
        lines.append("%d alert(s). Nothing was changed: this monitor observes and "
                     "reports. Acting on an alert is a maintainer decision."
                     % len(rep["alerts"]))
    else:
        lines.append("")
        lines.append("QUIET — no consumable official artifact satisfies an exit "
                     "condition and no upstream evidence contradicts the ledger.")
    return "\n".join(lines)


# --- self-test ---------------------------------------------------------------

def _self_test():  # noqa: C901
    fails = []

    def ck(name, cond):
        print(("ok   - " if cond else "FAIL - ") + name)
        if not cond:
            fails.append(name)

    ck("apk 3.5.7-r0 < 3.5.8-r0", cmp_version("apk", "3.5.7-r0", "3.5.8-r0") == -1)
    ck("apk 3.5.8-r0 satisfies 3.5.8-r0", satisfies("apk", "3.5.8-r0", "3.5.8-r0"))
    ck("apk 3.5.7-r1 does NOT satisfy 3.5.8-r0",
       not satisfies("apk", "3.5.7-r1", "3.5.8-r0"))
    ck("apk revision breaks the tie: 3.5.8-r1 > 3.5.8-r0",
       cmp_version("apk", "3.5.8-r1", "3.5.8-r0") == 1)
    ck("gomod v0.142.0 does NOT satisfy the 0.144.0 CRITICAL floor",
       not satisfies("gomod", "v0.142.0", "v0.144.0"))
    ck("gomod v0.144.0 satisfies the 0.144.0 floor",
       satisfies("gomod", "v0.144.0", "v0.144.0"))
    ck("gomod v0.145.0 satisfies the 0.144.0 floor",
       satisfies("gomod", "v0.145.0", "v0.144.0"))
    ck("gomod pre-release ordering is refused, not guessed",
       cmp_version("gomod", "v0.144.0-rc1", "v0.144.0") is None)
    ck("...and a refused comparison never satisfies a floor",
       not satisfies("gomod", "v0.144.0-rc1", "v0.144.0"))
    ck("deb versions are never ordered by this comparator",
       cmp_version("deb", "3.0.20-1~deb12u2", "3.0.20-1~deb12u3") is None)
    ck("a missing observation never satisfies a floor",
       not satisfies("apk", None, "3.5.8-r0"))

    watch = _load_yaml(WATCH)
    ledger = load_ledger()
    cohort, problems = bind_groups(watch, ledger)
    ck("watch config binds cleanly to the live ledger (%d problems)" % len(problems),
       not problems)
    ck("the fail-closed cohort is non-empty (%d records)" % len(cohort), len(cohort) > 0)

    # Movement fixtures replaying the two real upstream events.
    def obs(aid, index, plats, inv):
        return {"observed_at": "2026-08-27T00:00:00Z", "artifacts": [{
            "id": aid, "index_digest": index,
            "platforms": {p: {"manifest_digest": d, "inventory": dict(inv),
                              "inventory_source": "fixture"}
                          for p, d in plats.items()}}]}

    art = next(a for a in watch["artifacts"] if a["id"] == "frankenphp-8.3-bookworm")
    base_p = art["baseline"]["platforms"]
    baseline_inv = {"github.com/getkin/kin-openapi": "v0.140.0",
                    "google.golang.org/grpc": "v1.81.1"}

    r = evaluate(watch, ledger, obs("frankenphp-8.3-bookworm", "sha256:" + "1" * 64,
                                    dict(base_p), baseline_inv))
    ck("INDEX movement alone is classified index-movement-only",
       r["binds"][0]["movement_class"] == "index-movement-only")
    ck("...and raises NO alert", r["alerts"] == [])

    r = evaluate(watch, ledger, obs("frankenphp-8.3-bookworm", "sha256:" + "2" * 64,
                                    {p: "sha256:" + "3" * 64 for p in base_p},
                                    baseline_inv))
    ck("BOTH platform manifests moving with unchanged content is platform-manifest-movement",
       r["binds"][0]["movement_class"] == "platform-manifest-movement")
    ck("...and raises NO alert", r["alerts"] == [])

    below = dict(baseline_inv, **{"github.com/getkin/kin-openapi": "v0.142.0"})
    r = evaluate(watch, ledger, obs("frankenphp-8.3-bookworm", art["baseline"]["index_digest"],
                                    dict(base_p), below))
    ck("content moving to v0.142.0 is a content-change",
       r["binds"][0]["movement_class"] == "content-change")
    ck("...but 0.142.0 is BELOW the 0.144.0 CRITICAL floor, so NO alert", r["alerts"] == [])

    at_floor = dict(baseline_inv, **{"github.com/getkin/kin-openapi": "v0.144.0"})
    r = evaluate(watch, ledger, obs("frankenphp-8.3-bookworm", art["baseline"]["index_digest"],
                                    dict(base_p), at_floor))
    ck("reaching v0.144.0 on BOTH platforms alerts exit-condition-met",
       [a["class"] for a in r["alerts"]] == [ALERT_EXIT_MET])
    ck("...and the alert names the three G21 ledger records",
       len(r["alerts"][0]["records"]) == 3)

    one_arch = {"observed_at": "2026-08-27T00:00:00Z", "artifacts": [{
        "id": "frankenphp-8.3-bookworm", "index_digest": art["baseline"]["index_digest"],
        "platforms": {
            "linux/amd64": {"manifest_digest": base_p["linux/amd64"], "inventory": at_floor},
            "linux/arm64": {"manifest_digest": base_p["linux/arm64"], "inventory": baseline_inv}}}]}
    r = evaluate(watch, ledger, one_arch)
    ck("a fix on ONE platform only does not clear (cohort is both children)",
       r["alerts"] == [])

    absent = {"observed_at": "2026-08-27T00:00:00Z", "artifacts": [{
        "id": "frankenphp-8.3-bookworm", "index_digest": art["baseline"]["index_digest"],
        "platforms": {p: {"manifest_digest": d, "inventory": dict(baseline_inv, libaom3="3.6.0-1+deb12u2")}
                      for p, d in base_p.items()}}]}
    r = evaluate(watch, ledger, absent)
    ck("libaom3 appearing in the base contradicts the recorded attribution",
       [a["class"] for a in r["alerts"]] == [ALERT_CONTRADICTED])

    r = evaluate(watch, ledger, {"observed_at": "x", "artifacts": []})
    ck("an artifact that was not observed is a GAP, never a clean result",
       len(r["gaps"]) == len(watch["artifacts"]) and r["alerts"] == [])

    rep = {"gaps": [], "notes": [], "alerts": []}
    evaluate_distro(watch, {"debian": {"openssl": {"suite": "bookworm-security",
                                                   "fixed": {"CVE-2026-14456": "3.0.21-1~deb12u1"}}}}, rep)
    ck("a published Debian fix contradicts fix_available: false",
       any(a["class"] == ALERT_CONTRADICTED for a in rep["alerts"]))
    rep2 = {"gaps": [], "notes": [], "alerts": []}
    evaluate_distro(watch, {"debian": {"openssl": {"suite": "bookworm-security", "fixed": {}}}}, rep2)
    ck("...and no published fix raises nothing", rep2["alerts"] == [])
    ck("Alpine availability alone never alerts",
       not any(a for a in rep2["alerts"]))

    cp = checkpoints(watch, ledger, "2026-09-15")
    ck("2026-09-15 makes the first-review checkpoint due",
       [c["id"] for c in cp["due"]] == ["first-review"])
    ck("the checkpoint names every fail-closed record, not a bare date",
       cp["record_count"] == len(cohort) and cp["record_count"] == 32)
    text = render_checkpoints(cp)
    ck("rendered checkpoint names groups", "G21" in text and "G22" in text)
    ck("rendered checkpoint names individual advisories",
       "GHSA-r277-6w6q-xmqw" in text and "CVE-2026-14456" in text)
    ck("rendered checkpoint states renewal is not automatic",
       "NOTHING IN THIS REPOSITORY RENEWS AN EXCEPTION" in text)
    ck("rendered checkpoint prompts a decision and does not schedule one",
       "PROMPT TO DECIDE" in text and "schedules nothing" in text)
    quiet = checkpoints(watch, ledger, "2026-01-01")
    ck("a date far from every checkpoint is silent", not quiet["active"])
    ck("...and renders as silence", "none due" in render_checkpoints(quiet))
    late = checkpoints(watch, ledger, "2026-09-28")
    ck("all three checkpoints are due once the deadline has passed",
       [c["id"] for c in late["due"]]
       == ["first-review", "final-evidence-refresh", "maintainer-decision-deadline"])

    print("----")
    print("upstream-monitor self-test: %s" % ("PASS" if not fails else "FAIL"))
    return 1 if fails else 0


# --- CLI ---------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("command", nargs="?", choices=["evaluate", "checkpoints"])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--watch", default=WATCH)
    ap.add_argument("--ledger", default=LEDGER)
    ap.add_argument("--observation", help="observation JSON from scripts/upstream-monitor.sh")
    ap.add_argument("--today", help="pin the date (YYYY-MM-DD); default is UTC today")
    ap.add_argument("--window-days", type=int, default=45)
    ap.add_argument("--json", action="store_true", help="emit the report as JSON")
    ap.add_argument("--fail-on-alert", action="store_true",
                    help="exit 3 when an alert fires, so a scheduled run turns red")
    ap.add_argument("--fail-on-checkpoint", action="store_true",
                    help="exit 4 when a checkpoint is due or upcoming")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if not args.command:
        ap.error("a command is required (evaluate | checkpoints) unless --self-test")

    watch = _load_yaml(args.watch)
    ledger = load_ledger(args.ledger)

    if args.command == "checkpoints":
        today = args.today or _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")
        rep = checkpoints(watch, ledger, today, args.window_days)
        print(json.dumps(rep, indent=2, sort_keys=True) if args.json else render_checkpoints(rep))
        if rep["binding_problems"]:
            return 5
        return 4 if (args.fail_on_checkpoint and rep["active"]) else 0

    if not args.observation:
        ap.error("evaluate requires --observation")
    with open(args.observation, encoding="utf-8") as fh:
        observation = json.load(fh)
    rep = evaluate(watch, ledger, observation)
    evaluate_distro(watch, observation, rep)
    rep["alert_count"] = len(rep["alerts"])
    rep["verdict"] = "ALERT" if rep["alerts"] else "QUIET"
    print(json.dumps(rep, indent=2, sort_keys=True) if args.json else render_verdict(rep))
    return 3 if (args.fail_on_alert and rep["alerts"]) else 0


if __name__ == "__main__":
    sys.exit(main())
