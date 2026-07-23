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
3. Verify the requested capability.
4. Resolve exact repository, ref, and path scope.
5. Compare cumulative usage to declared budgets.
6. match the active claim and fencing generation.
7. verify action-specific approval gates.

Any violation denies the request.

## Path rules

- Paths use forward-slash-separated repository-relative form.
- Absolute paths and `..` segments are invalid.
- Deny patterns win over allow patterns.
- A trailing `/**` includes the named directory and all descendants.
- Other patterns use case-sensitive glob matching in the reference implementation.

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

## Compatibility questions for upstream discussion

1. Should permits be replaceable application data, a Buzz custom kind, or a new interoperable NIP?
2. Should an agent action carry the permit digest, full permit, or a relay reference?
3. Which actor supplies trusted receipt time for expiry?
4. Should NIP-OA attest owner provenance while PermitMesh constrains each task, or should the formats converge?
5. Where should revocation and the current fencing generation live?
