#!/usr/bin/env python3
"""Extract ONE workflow step's executable body, so a test can RUN it.

WHY THIS EXISTS.

    grep -rq 'scripts/license/' .github/workflows/

is the assertion that let the image-SBOM licence gap survive: it matched
ci.yml's single `--self-test` line and reported the gate as wired. A name
appearing in YAML proves nothing about whether the gate runs, what it is handed
or whether anybody reads the answer.

So the tests do not grep. They PARSE the workflow with a real YAML parser, take
the exact `run:` body of a named step, and EXECUTE it with the inputs the step
declares. If somebody deletes the step, weakens its flags or stops consuming its
result, the executed body changes and the sabotage assertions stop refusing.

Usage:
  workflow_step.py <workflow.yml> <job-id> <step-id> --run
  workflow_step.py <workflow.yml> <job-id> <step-id> --env      # KEY=VALUE lines
  workflow_step.py <workflow.yml> <job-id> <step-id> --env-keys # KEY lines
  workflow_step.py <workflow.yml> <job-id> --step-ids
  workflow_step.py <workflow.yml> --job-named <name> --run-containing <text>

--env omits any value carrying a ${{ }} expression: those are supplied by
GitHub, not by the file, and a test that pretended otherwise would be asserting
against its own invention. --env-keys still lists them, so a caller can prove it
supplied every input the step reads.
"""
import re
import sys

import yaml

EXPR = re.compile(r"\$\{\{")


def load(path):
    with open(path) as fh:
        return yaml.safe_load(fh)


def find_job(wf, job_id=None, named=None):
    jobs = wf.get("jobs") or {}
    if job_id is not None:
        if job_id not in jobs:
            sys.stderr.write("no job %r in this workflow (have: %s)\n"
                             % (job_id, ", ".join(sorted(jobs))))
            raise SystemExit(2)
        return jobs[job_id]
    for jid, job in jobs.items():
        if (job.get("name") or jid) == named:
            return job
    sys.stderr.write("no job named %r\n" % named)
    raise SystemExit(2)


def find_step(job, step_id):
    for st in job.get("steps") or []:
        if st.get("id") == step_id or st.get("name") == step_id:
            return st
    sys.stderr.write("no step %r in that job\n" % step_id)
    raise SystemExit(2)


def main(argv):
    path = argv[0]
    wf = load(path)
    rest = argv[1:]
    if rest and rest[0] == "--job-named":
        job = find_job(wf, named=rest[1])
        want = rest[3] if len(rest) > 3 and rest[2] == "--run-containing" else None
        for st in job.get("steps") or []:
            body = st.get("run") or ""
            if want and want in body:
                sys.stdout.write(body)
                return 0
        sys.stderr.write("no step in job %r runs anything containing %r\n"
                         % (rest[1], want))
        return 2
    job = find_job(wf, job_id=rest[0])
    if rest[1] == "--step-ids":
        for st in job.get("steps") or []:
            if st.get("id"):
                print(st["id"])
        return 0
    step = find_step(job, rest[1])
    mode = rest[2]
    if mode == "--run":
        body = step.get("run")
        if not body:
            sys.stderr.write("step %r has no run: body (it is a `uses:` step)\n" % rest[1])
            return 2
        sys.stdout.write(body)
        return 0
    env = step.get("env") or {}
    if mode == "--env-keys":
        for k in sorted(env):
            print(k)
        return 0
    if mode == "--env":
        for k in sorted(env):
            v = str(env[k])
            if EXPR.search(v):
                continue
            print("%s=%s" % (k, v))
        return 0
    sys.stderr.write("unknown mode %r\n" % mode)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
