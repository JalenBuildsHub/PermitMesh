# PermitMesh Protocol 0.1

Status: exploratory draft

## Roles

- **Issuer**: the human or system authorized to define the permit.
- **Subject**: the agent whose proposed actions are evaluated.
- **Evaluator**: the deterministic policy decision point.
- **Enforcer**: the runtime, relay, proxy, or tool host that refuses denied actions.
- **Approver**: a configured principal whose approval can satisfy a gate.

## Decision contract

For a structurally valid permit and request, an evaluator returns:

```json
{
  "allowed": false,
  "contract_digest": "<sha256>",
  "violations": ["<stable human-readable rule violation>"],
  "checks": ["validity_window", "capability", "repository_ref_path"]
}
```

Evaluators should collect all independently observable violations in one pass. This makes a denial useful for both humans and agents and avoids iterative “fix one thing, discover another” loops.

## Evaluation order

1. Validate the permit structure and semantic invariants.
2. Establish trusted evaluation time.
3. Bind the request subject to the permit subject.
4. Verify the requested capability.
5. Resolve exact repository, ref, and path scope.
6. Compare cumulative usage to declared budgets.
7. Match the active claim and fencing generation.
8. Verify action-specific approval gates.

Any violation denies the request.

When `scope.channels` is non-empty, an action request must name one configured
channel. The evaluator also binds every request to `subject.id`; a trusted
adapter must authenticate the caller before populating that field.

`read` and `edit` are file-oriented capabilities and require a path. Other
capabilities are repository-level decisions; if an adapter supplies a path, it
is still checked. A shell authorization does not implicitly authorize file
effects—the enforcement adapter must separately evaluate resulting reads or
edits or provide an equivalent trusted interception boundary.

PermitMesh is a domain profile for software-change decisions. It does not
define a new policy language, credential, delegation chain, or enforcement
protocol. An implementation may evaluate the profile directly or translate it
to a general system such as OPA, Cedar, Biscuit, or an OAuth authorization
detail. The translation must preserve fail-closed behavior.

## Path rules

- Paths use forward-slash-separated repository-relative form.
- Absolute paths and `..` segments are invalid.
- Deny patterns win over allow patterns.
- A trailing `/**` includes the named directory and all descendants.
- Other patterns use case-sensitive, path-segment-aware glob matching. For
  example, `src/*` does not match `src/package/module.py`; use `src/**` for
  descendants.

Production adapters must decide whether repository name and path comparison should be case-sensitive on their target filesystem. The decision must be consistent between evaluation and enforcement.

## Claims and fencing

A `claim_id` states which unit of work owns the action. A monotonically increasing `fencing_generation` makes an older worker distinguishable after transfer or recovery.

The protected resource must compare the supplied generation with its current generation. Including the number in a permit without enforcement at the protected resource does not prevent stale writers.

## Digests and signatures

The contract digest is:

```text
sha256(UTF-8(canonical-json(contract minus signature and contract_digest)))
```

Canonical JSON uses sorted object keys, no insignificant whitespace, and UTF-8 characters without ASCII escaping.

The digest provides stable content identity, not authorship. Signature verification is deliberately outside the 0.1 reference core so integrations cannot accidentally confuse “hash matches” with “authorized issuer signed.”

## Nostr transport experiment

`permitmesh to-event` creates an explicitly unsigned envelope containing a kind `30078` application-data template:

- `d`: `permitmesh:contract:<digest>`
- `t`: `permitmesh`
- `p`: subject public key or principal identifier
- `x`: contract digest
- `content`: canonical contract JSON

The adapter requires lowercase hex Nostr public keys, sets the issuer `pubkey`, leaves `id` and `sig` empty, and labels the outer envelope `unsigned_template`. A Nostr implementation must compute the NIP-01 event ID and create a valid Schnorr signature before publishing the inner event.

## Conformance receipts

`permitmesh conformance` runs deterministic fixtures and emits a 0.1 receipt.
The receipt binds to the canonical suite digest and records:

- implementation name and version;
- expected and observed outcome for every case;
- the decision or malformed-input result;
- pass/fail totals; and
- a caller-supplied description of the actual enforcement boundary.

The receipt is not signed and is not proof that a runtime enforced a decision.
It is reproducible interoperability evidence. Cryptographic authorization
evidence and execution closure records belong to stronger systems such as the
emerging SCITT/WIMSE Permit work.

See `schema/permitmesh-conformance-receipt.schema.json` and
`examples/conformance-suite.json`.

## Completion evidence

`permitmesh verify-completion` checks a declared completion report against
`validation.required_commands` and `validation.required_artifacts`. The report
is bound to subject, claim, fencing generation, and the validity window.

The command checks completeness of the declaration only. It does not execute a
command, hash an artifact, authenticate an approval, or prove that the claimed
evidence is true. A production adapter must obtain those facts from trusted
execution and artifact systems.

## Compatibility questions for upstream discussion

1. Should permits be replaceable application data, a Buzz custom kind, or a new interoperable NIP?
2. Should an agent action carry the permit digest, full permit, or a relay reference?
3. Which actor supplies trusted receipt time for expiry?
4. Should NIP-OA attest owner provenance while PermitMesh constrains each task, or should the formats converge?
5. Where should revocation and the current fencing generation live?
