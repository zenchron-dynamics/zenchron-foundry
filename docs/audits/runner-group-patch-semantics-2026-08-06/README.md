# Runner-group PATCH semantics — measured, 2026-08-06

Whether a runner-group `PATCH` that omits `selected_repository_ids` **preserves**
or **clears** repository membership. The answer decides how every future
workflow-allowlist change must be performed.

## 1. Documented API schema

- `selected_repository_ids` is valid when **creating** a runner group.
- It is valid on the dedicated `PUT .../runner-groups/{id}/repositories`, which
  replaces the selected repository list.
- It is **not** a permitted field on the runner-group `PATCH`; sending it returns
  `422 "selected_repository_ids" is not a permitted key`.
- `PATCH` accepts group properties and `selected_workflows`, and says nothing
  about repository membership.

The documentation therefore establishes what may be sent. It does not say what
happens to membership when the field is absent, which is the only question that
matters here.

## 2. Behaviour measured by the canary

A throwaway group was created with one repository, zero runners and one
master-pinned workflow, then a **real** keyless workflow mutation was performed
(`build-images.yml` → `stage-and-authorize.yml`, not a no-op, so the backend
mutation path actually executed).

| step | repositories |
|---|---|
| after create | `[1254295268]` |
| after keyless `PATCH` (HTTP 200) | **`[]`** |
| after `PUT .../repositories` | `[1254295268]` |

**Verdict: CLEARED.** Runners stayed `[]`, `visibility` stayed `selected`,
`restricted_to_workflows` stayed `true`, and the workflow set became exactly what
was requested.

The `PATCH` returned **200 OK while emptying the selection**. A success status is
not evidence that a mutation did what was asked; only a postcondition read can
tell the difference.

Every call used API version `2026-03-10`.

## 3. Inference used for the replacement helper

The 2026-08-02 incident and this measurement are the same behaviour. The old
guardrail's *rationale* was right — a bare workflow PATCH destroys membership —
but its *mechanism* (require the field in the payload) is now impossible, because
GitHub rejects the field.

So the rule inverts:

- the PATCH must **not** carry `selected_repository_ids`, `runners` or
  `repositories`; those belong to their own endpoints;
- the repository list becomes a **separate mandatory argument**;
- a `PUT` of the complete desired list is **unconditional** after every
  successful PATCH — never skipped because a read happened to look correct;
- every postcondition is re-read and compared;
- on failure, membership is restored **first**, and because the rollback is
  itself a PATCH that clears membership again, the list is restored a **second**
  time afterwards.

**This is not transactional.** Two REST calls cannot be made atomic. The honest
guarantee is: a workflow PATCH opens a measured **fail-closed availability
window** in which no repository is authorised and trusted jobs are
unschedulable; the helper closes it immediately, verifies closure, and treats a
failure to restore membership as an incident.

## 4. Production group 3 was never addressed

No call in this experiment targeted `zenchron-foundry-trusted` (id 3). It was
read before and after and is unchanged: 10 workflows, `[1254295268]`.
`groups-after-delete.json` records the org's groups afterwards.

## 5. The temporary group

Zero runners for its entire life, access to only the already-authorised
repository, every workflow pinned to `refs/heads/master`, no workflow dispatched.
Deleted after evidence capture, and its absence verified.

## Contents

`result.json` is the canary's own record, byte-identical to the file it produced.
`canary.sh` is the script that ran. The remaining files are the request/response
pairs and snapshots at each step. Verify with:

```sh
shasum -a 256 -c SHA256SUMS
```
