# Contributing

PermitMesh is at the problem-validation stage. The most valuable contribution is a small, redacted real-world fixture showing:

1. the action an agent attempted;
2. the narrow authority the maintainer intended;
3. whether PermitMesh allowed or denied it correctly; and
4. which runtime could enforce the decision.

Before proposing new schema fields, include an example that cannot be represented safely with the current format.

Run:

```powershell
$env:PYTHONPATH = "$PWD\src"
python -m unittest discover -s tests -v
python -m compileall -q src tests
python -m permitmesh conformance examples\conformance-suite.json
```

Contributions must preserve fail-closed behavior, exhaustive denial reasons,
deterministic digests, exact high-risk operation binding, explicit replay
state, and explicit signed/unsigned states. Do not describe nonce checks as
one-time enforcement unless the enforcement point atomically consumes the
nonce with execution.
