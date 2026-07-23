# Threat Model

PermitMesh 0.1 is a policy format and reference decision engine. It becomes a security control only when an enforcement point asks for a decision before every protected action and refuses denied or unverifiable requests.

## Assets

- source code and repository history;
- deployment and publishing authority;
- credentials and private workspace content;
- compute and monetary budgets;
- human approval integrity;
- attribution and audit evidence.

## Adversaries and failures

| Threat | 0.1 control | Remaining risk |
| --- | --- | --- |
| Agent acts outside assigned files | allow/deny path checks | runtime may bypass evaluator |
| Agent reuses stale ownership | exact claim plus fencing generation | protected resource must enforce current generation |
| Agent exceeds bounded work | file, command, and cost limits | adapter must supply trustworthy cumulative usage |
| Agent performs consequential action silently | per-action approval thresholds | approval authenticity is adapter-specific |
| Agent backdates an expired permit | request timestamps never control authorization time | adapter must protect the evaluator's clock |
| Permit content is modified | canonical SHA-256 digest | digest alone does not prove issuer identity |
| Forged issuer or approval | no claimed protection in 0.1 core | signature verification is required before production |
| Path traversal | absolute and parent traversal rejection | symlinks and filesystem canonicalization are enforcer concerns |
| Confused deputy across repos | exact repository/ref/path match | repository identity must be bound to a trusted canonical ID |

## Security invariants

1. Invalid contracts and unknown capabilities fail closed.
2. Deny rules override allow rules.
3. Approval is scoped to configured actions and principals.
4. A stale fencing generation cannot authorize an action.
5. The CLI never labels an unsigned event as signed.
6. No marketing claim may describe the reference validator as a sandbox.

## Not yet implemented

- NIP-01 or NIP-OA signature verification;
- revocation distribution;
- protected evaluator clock and relay receipt proofs;
- symlink-safe filesystem enforcement;
- integration with Buzz relay, MCP, ACP, Goose, Codex, or Claude Code;
- cumulative budget storage across requests;
- formal verification or external security review.

These are release gates, not hidden assumptions.
