# PermitMesh Launch Campaign

Status: draft; no external messages sent

## Positioning

- **Category:** portable capability contracts for workspace agents
- **One line:** Buzz gives every agent an identity. PermitMesh gives each piece of work an exact authority boundary.
- **Proof:** one command allows a narrow source edit; the same evaluator denies an over-scoped deploy with eight explicit reasons.
- **Ask:** help decide where this primitive belongs and break the v0.1 policy model with real workflows.

## Audience

Primary:

- Buzz maintainers and early self-hosting teams;
- Nostr protocol contributors interested in agents;
- maintainers experimenting with Goose, Codex, Claude Code, or MCP tools.

Secondary:

- agent-runtime authors who need a portable policy decision format;
- security engineers working on agent authorization and provenance.

## Launch sequence

1. Publish the Apache-2.0 repo after Jalen's approval.
2. Confirm the clean-install demo and CI on the public clone.
3. Open one design-first discussion in the venue Buzz's contribution guide prefers.
4. Publish the short X thread below with the runnable proof.
5. Personally onboard three maintainers and ask for a redacted allow/deny receipt.
6. Publish findings after 10–14 days, including reasons the idea may be wrong.

Do not carpet-post communities, ask for stars, or describe the project as a security sandbox.

## X launch draft

### Post 1

Buzz gives people and agents the same cryptographic identity.

That solves “who did this?”

The next question is “what, exactly, were they allowed to do?”

We built a small open experiment called PermitMesh.

### Post 2

A PermitMesh contract scopes an agent to:

- exact repos, refs, channels, and paths
- allowed actions
- time, file, command, and cost budgets
- human approval gates
- a live claim + fencing generation
- required validation evidence

One portable JSON document. Deterministic decisions.

### Post 3

The demo allows a normal source edit.

Then it denies a deploy for eight reasons at once: wrong ref, forbidden path, exceeded budgets, stale claim, stale fence, and missing approval.

No model decides. No vague “be careful” prompt.

### Post 4

This is not affiliated with Block, not a Buzz fork, and not a sandbox.

It is a question in runnable form:

Should task-scoped agent permits complement NIP-OA and travel as signed workspace events?

We want maintainers to break the idea with real workflows.

## Upstream discussion draft

**Title:** Design question: task-scoped capability contracts for agent work

Buzz's signed identities and NIP-OA draft establish valuable provenance: an agent authors its own event, and an owner can attest that relationship under bounded event conditions.

We are exploring a complementary work-level contract for constraints that do not fit identity alone: repository/ref/path scope, action capabilities, budgets, approval gates, a live claim and fencing generation, and required validation evidence.

The local proof is transport-neutral and can emit an explicitly unsigned kind-30078 application-data template. We have not assumed that this is the right event kind or that Buzz should adopt the format.

Questions:

1. Is task-level authorization already planned elsewhere in Buzz?
2. Would this fit best as application data, a Buzz-specific event, an extension to owner attestation, or outside the relay entirely?
3. Which component should provide trusted expiry, revocation, and current fencing state?
4. Would a small conformance fixture be useful before any integration proposal?

If the direction is redundant or belongs elsewhere, that answer is useful too.

## Forty-five-second demo script

1. “This permit allows one build agent to edit source and tests on a feature ref.”
2. Run the allowed fixture and point to `"allowed": true`.
3. “Now the agent tries to deploy from main, touches `.env`, exceeds every budget, and presents a stale claim.”
4. Run the denied fixture and scan the eight reasons.
5. “The same contract can be wrapped in a Nostr event, but we deliberately leave it unsigned until a real key adapter signs it.”
6. Close: “Identity tells us who acted. PermitMesh tests whether the action was inside the job.”

## Measurement

The campaign succeeds at five verified external authorization runs across at least two teams, with zero known false allows. Views, likes, reposts, and stars are diagnostic discovery signals only.

## Authority boundary

This document is ready to use after Jalen approves public publishing. It does not authorize creating a public repository, posting to X, contacting maintainers, or opening an upstream discussion.
