# Prior art and differentiation

Research date: 2026-07-23

## Release conclusion

PermitMesh is **not** a new policy language, identity protocol, capability-token
system, signature format, delegation scheme, enforcement proxy, or audit ledger.
Each of those categories already has mature work or active standards proposals.

The defensible experiment is narrower:

> Can an implementation-neutral profile for software-changing agents make
> repository, ref, path, budget, approval, live-claim fencing, and required-proof
> constraints portable across agent runtimes, while producing a common
> conformance receipt?

This review found no cited specification that standardizes that exact
software-change combination. Most general authorization systems can encode it,
and several emerging agent-authorization drafts cover adjacent task, approval,
delegation, and receipt concerns more deeply. PermitMesh should therefore be
judged as a small domain profile and conformance lab, not a competing security
architecture.

If external implementers do not find the software-change profile useful, the
right outcome is to contribute the fixtures to a stronger upstream system and
retire the standalone format.

## Comparison

| System | What it already does | What PermitMesh must not claim | Narrow gap tested here |
| --- | --- | --- | --- |
| OAuth Rich Authorization Requests (RFC 9396) | Carries fine-grained JSON authorization details, including actions, locations, identifiers, and API-specific fields. | Fine-grained or structured authorization as a new idea. | A fixed, non-OAuth software-change vocabulary plus conformance cases. |
| Open Policy Agent / Rego | General-purpose context-aware policy decisions; services remain enforcement points. | Inventing the PDP/PEP split or general policy-as-code. | A portable data profile that does not require adopters to share a policy language. |
| Cedar | Evaluates principal, action, resource, and context against typed policies. | Inventing deterministic fine-grained authorization. | A concrete workspace-agent resource model and receipt suite. |
| Macaroons | Cryptographic bearer capabilities with contextual caveats and decentralized delegation. | Inventing caveats, attenuation, or scoped credentials. | No credential design; only a software-work constraint vocabulary. |
| Eclipse Biscuit | Signed, offline-verifiable, attenuable tokens with a Datalog policy language. | Stronger or more complete token security. Biscuit is substantially ahead here. | PermitMesh fields could become a Biscuit vocabulary or adapter if the profile proves useful. |
| UCAN | Public-key-verifiable, delegable capabilities for agents identified by DIDs, with invocation and revocation sub-specifications. | Inventing distributed capability delegation, proof chains, or agent principals. | PermitMesh has no delegation protocol; it tests a software-change constraint and evidence profile that could be carried by UCAN. |
| ZCAP-LD | Signed capability delegation chains, invocation targets, allowed actions, expiry, and caveats. | Inventing signed delegated capabilities. | Repository lifecycle and proof-of-work semantics are not standardized by ZCAP-LD. |
| SPIFFE / SVID | Portable cryptographic workload identity and trust-domain federation. | Solving workload identity. | PermitMesh can use a SPIFFE ID as issuer or subject; it does not replace SVIDs. |
| MCP authorization | OAuth-based authorization, audience binding, token validation, and least-privilege scopes for MCP servers. | Securing MCP authentication or access-token handling. | Task-level software-change constraints sit above server access. |
| Agent Identity Protocol draft | Agent identity, signed tool calls, an enforcement proxy, allow/ask/block rules, HITL, DLP, and append-only audit records. | Inventing agent-specific proxy enforcement or HITL. | AIP is tool-call shaped; PermitMesh tests repo/ref/path, cumulative work budgets, claim fencing, and required validation outputs. |
| AI Agent Authentication and Authorization draft | Composes WIMSE, SPIFFE, OAuth, and related standards for agent identity and authorization. | Being a general agent identity or authorization architecture. | A dependency-free implementation profile for local software changes. |
| Mission-Bound Authorization draft | Defines durable, human-approved task authority spanning OAuth tokens and lifecycle state. | Inventing durable task-scoped authorization. | A non-OAuth software-maintenance profile with deterministic offline fixtures. |
| Attenuating Authorization Tokens draft | Defines signed task-scoped delegation tokens with tool and argument constraints and offline attenuation. | Inventing task-scoped delegation. | PermitMesh deliberately has no delegation model in 0.1. |
| SCITT/WIMSE Permit drafts | Define signed pre-execution authorization evidence, closure records, request binding, and verifiable receipts. | Inventing "permits" or signed authorization receipts. | PermitMesh receipts are unsigned conformance evidence for the software-change profile, not cryptographic audit evidence. |
| SPT-Txn draft | Transaction-bound action/resource tokens with attenuation, attestation, revocation, and signed receipts. | Transaction-bound authorization or tamper-evident receipts. | A much smaller, readable workspace profile suitable for local runtime adapters. |

## The unsupported combination

The v0.1 profile combines these fields in one decision contract:

1. named issuer and agent subject;
2. repository, ref, channel, allow-path, and deny-path scope;
3. software-work capabilities;
4. trusted validity window;
5. cumulative file, command, and cost ceilings;
6. action-specific approval thresholds;
7. live claim identity and monotonic fencing generation;
8. required validation commands and artifacts; and
9. a portable adversarial suite with an explicit enforcement-boundary receipt.

That combination is the release hypothesis. It is not a claim that the
individual mechanisms are novel.

## Primary sources

- [RFC 9396: OAuth 2.0 Rich Authorization Requests](https://datatracker.ietf.org/doc/html/rfc9396)
- [Open Policy Agent](https://github.com/open-policy-agent/opa)
- [Cedar authorization model](https://docs.cedarpolicy.com/auth/authorization.html)
- [Macaroons paper](https://research.google/pubs/macaroons-cookies-with-contextual-caveats-for-decentralized-authorization-in-the-cloud/)
- [Eclipse Biscuit specification](https://doc.biscuitsec.org/reference/specifications)
- [User Controlled Authorization Network specification](https://github.com/ucan-wg/spec)
- [Authorization Capabilities for Linked Data](https://w3c-ccg.github.io/zcap-spec/)
- [SPIFFE standard](https://spiffe.io/docs/latest/spiffe-specs/)
- [MCP authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)
- [Agent Identity Protocol draft](https://datatracker.ietf.org/doc/draft-aip-agent-identity-protocol/)
- [AI Agent Authentication and Authorization draft](https://datatracker.ietf.org/doc/draft-klrc-aiagent-auth/)
- [Mission-Bound Authorization for OAuth 2.0 draft](https://datatracker.ietf.org/doc/draft-mcguinness-oauth-mission/)
- [Attenuating Authorization Tokens draft](https://datatracker.ietf.org/doc/draft-niyikiza-oauth-attenuating-agent-tokens/)
- [Signed Authorization-Evidence Records for WIMSE draft](https://datatracker.ietf.org/doc/draft-munoz-wimse-authorization-evidence/)
- [Transaction-Bound Authorization Tokens draft](https://datatracker.ietf.org/doc/draft-coetzee-oauth-spt-txn-tokens/)

Internet-Drafts are works in progress, not IETF-endorsed standards. Their rapid
growth is evidence that the category is active and crowded, not proof that any
one proposal will become canonical.
