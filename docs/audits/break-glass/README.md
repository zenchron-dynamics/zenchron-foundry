# Break-glass records

A single maintainer will occasionally need to bypass a control — a broken gate
blocking a security fix, for example. Pretending otherwise produces silent
bypasses; making the bypass *recordable* produces evidence.

One YAML file per bypass, named `break-glass-YYYY-MM-DD-NN.yaml`. The required
fields and the retrospective deadline are defined in
[`policies/governance-model.yaml`](../../../policies/governance-model.yaml)
(`break_glass:`), and `scripts/assert-governance-model.sh` **fails the build**
when a record is open past its deadline without a retrospective.

The point is not to forbid the bypass. It is to make an unexamined one
impossible to leave lying around.

See `break-glass-EXAMPLE.yaml` for the shape. It is an example, not a record: it
carries `example: true` and the tooling ignores it.
