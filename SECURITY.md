# Security Policy

PermitMesh is pre-1.0 experimental software and is not yet a complete security boundary.

Please do not include credentials, private repository data, or exploitable third-party details in a public report. Until a dedicated private reporting address is published, open a minimal GitHub issue asking for a private contact channel.

The following are expected limitations in 0.1 and should not be reported as novel vulnerabilities:

- the core CLI does not verify cryptographic signatures;
- the demo request timestamp is caller-supplied;
- the core does not sandbox tools or enforce decisions;
- subject, channel, approval, usage, claim, fence, and completion facts are
  trusted adapter inputs rather than authenticated by the core;
- cumulative budget storage and revocation are not implemented.

Unexpected false allows, path-matching escapes, digest inconsistencies, and misleading signed/unsigned states are in scope.
