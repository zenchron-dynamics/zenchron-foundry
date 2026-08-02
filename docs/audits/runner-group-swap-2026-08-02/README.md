# Runner-group workflow allowlist swap — 2026-08-02

Org runner group **3** (`zenchron-foundry-trusted`), the fork-PR boundary
established by [#96](https://github.com/zenchron-dynamics/zenchron-foundry/issues/96).

## Incident classification

> **Fail-closed runner-group availability incident detected and recovered during
> an authorized workflow allowlist change.**

It was **not** a privilege exposure:

- no unauthorized repository gained runner access;
- the sole authorized repository temporarily lost access;
- trusted jobs would have become unschedulable;
- the postcondition verification detected the mutation;
- repository membership was restored through the dedicated endpoint;
- the full runner-group state was then revalidated.

That distinction matters for future audits: the blast radius was availability,
not confidentiality or integrity.

## What changed, and why

`#131` merged as `01a1181`, which removed the build matrix from `ci.yml` — it is
now five statically GitHub-hosted jobs and needs no privileged runner — and
added `trusted-validation.yml`, which does. The allowlist had to follow:

```diff
- zenchron-dynamics/zenchron-foundry/.github/workflows/ci.yml@refs/heads/master
+ zenchron-dynamics/zenchron-foundry/.github/workflows/trusted-validation.yml@refs/heads/master
```

Applied as one atomic PATCH. Workflow count unchanged (10); the other nine
entries preserved exactly.

## The incident

The PATCH changed only `selected_workflows`. It also **cleared the repository
selection**: `total_count` went `1 → 0`.

GitHub's runner-group PATCH treats an omitted `selected_repository_ids` as *set
to empty*, even when the field is nowhere in the request body. With
`visibility: selected` and zero selected repositories, **no** repository could
schedule on the pool.

Detected by the postcondition check `repository selection unchanged`, which
compared the re-fetched live state against the pre-mutation snapshot. A `200 OK`
on the PATCH was not evidence that it had done only what was asked.

Recovery, through the dedicated endpoint rather than another whole-group PATCH:

```http
PUT /orgs/zenchron-dynamics/actions/runner-groups/3/repositories
{"selected_repository_ids":[1254295268]}
```

Then the **complete** postcondition set was re-run against live state and passed:
`restricted_to_workflows` true, workflow count unchanged, `ci.yml` absent,
`trusted-validation.yml` present exactly once, every workflow pinned to
`@refs/heads/master`, no duplicates, only the intended entry changed, id / name /
visibility / `allows_public_repositories` / `workflow_restrictions_read_only`
unchanged, repository selection restored, runner membership unchanged.

## Guardrails added

**Declarative** — `policies/repository-governance.yaml` documents the hazard
beside `selected_repository_ids`, and the verifier already asserts exactly one
selected repository, the exact ID, no other public repository, the exact
workflow set, master-pinning, exact runner membership, and zero runners in the
`Default` group.

**Mutation/runbook** — `scripts/admin/runner-group-patch.sh`. A declarative
policy cannot stop a hand-written `curl`, so the helper:

1. snapshots the full group, its repositories and its runners first;
2. **refuses** to send a PATCH whose payload omits `selected_repository_ids`
   (verified against the actual payload that caused this incident);
3. re-fetches and diffs everything afterwards — a 200 is not evidence;
4. restores from the snapshot and stops if any unrelated field moved.

Self-test: 14 cases, including the exact incident payload and each unsafe
end-state (cleared repositories, changed runner membership, widened visibility,
dropped workflow restriction, non-master pin, unrelated field change).

## Live boundary verification

Dispatched `trusted-validation.yml` from `master`, `mode=pr` against PR #132 so
the run publishes no commit statuses on `master`:

- run [`30740447770`](https://github.com/zenchron-dynamics/zenchron-foundry/actions/runs/30740447770)
- input SHA `9c3b9536e04fe4247aa61e9beeda560e82c714ce`

Result — **runner-boundary and scheduling evidence, not successful validation
evidence**:

| Stage | Outcome |
|---|---|
| `authorize` (GitHub-hosted) | success — exact-head + open-PR gate passed |
| all 10 matrix legs | reached **self-hosted runners**, across *both* `runner-prod-fsn1-org-zenchron-dynamics-1` and `-2` |
| checkout / build / smoke / Trivy scan | success on every leg |
| reconciliation gate | **failed on every leg** |
| `stale-exception check` | `skipped` — its `validate.result == 'success'` guard |
| `publish release statuses` | `skipped` — `pr` mode only |
| `seal` | `failure` — refuses a skipped aggregate |

The reconciliation failure is expected and explains itself: `master`'s
`trusted-validation.yml` (from #131) passes `--arch`, but `master`'s
`reconcile-vulnerabilities.sh` predates the mandatory-`--arch` work in #136,
which is not merged. It is an integration gap between a merged and an unmerged
PR, not a runner-boundary defect.

The downstream `skipped`/`failure` chain is the fail-closed design working in
production: a skipped aggregate is not a pass.

## Files

| File | Contents |
|---|---|
| `runner-group-before.json` | full group state before the PATCH |
| `runner-group-after-patch.json` | immediately after the PATCH (repository selection cleared) |
| `runner-group-restored.json` | after recovery and revalidation |
| `patch-payload.json` | the request body sent |
| `patch-response.json` | the API response |
| `selected-repositories-{before,after-patch,restored}.json` | `total_count` 1 → 0 → 1 |
| `runners-{before,after}.json` | runner membership, unchanged throughout |
| `trusted-validation-run-30740447770.json` | run metadata |
| `trusted-validation-jobs.json` | per-job status, conclusion and assigned runner |
| `fork-boundary-output.txt` | `assert-pr-workflows-github-hosted.sh` |
| `governance-pre-sync-output.txt` | verifier **before** the policy was synced |
| `SHA256SUMS` | checksums for everything above |

`governance-pre-sync-output.txt` is retained deliberately: it shows the verifier
correctly reporting the two divergences this swap created — `ci.yml` declared but
not live, `trusted-validation.yml` live but undeclared — before
`repository-governance.yaml` was updated to match. Every other runner-group
assertion passed in that same run, including the restored repository selection.

Sanitised: no credentials, authorization headers, cookies, runner tokens, signed
or temporary URLs, or absolute host paths. Verified with `gitleaks` and pattern
scans. The unsanitised 19-file working bundle is retained outside the repository.
