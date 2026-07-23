# Security Policy

PermitMesh is pre-1.0 experimental software and is not a complete security boundary.

Please report suspected vulnerabilities through
[GitHub private vulnerability reporting](https://github.com/JalenBuildsHub/PermitMesh/security/advisories/new).
Do not include credentials, private repository data, or exploitable
third-party details in a public issue. We aim to acknowledge private reports
within five business days; this is a response target, not a remediation SLA.

## Supported versions

| Version | Security fixes |
| --- | --- |
| Latest 0.2.x release | Yes |
| 0.1.x and earlier releases | No |

The following are expected limitations in 0.2 and should not be reported as novel vulnerabilities:

- the core CLI does not verify cryptographic signatures;
- the demo request timestamp is caller-supplied;
- the core does not sandbox tools or enforce decisions;
- subject, channel, approval, usage, claim, fence, and completion facts are
  trusted adapter inputs rather than authenticated by the core;
- cumulative budget storage and revocation are not implemented.
- the core checks caller-supplied consumed-nonce state but does not persist or
  atomically consume nonces with tool execution.

Unexpected false allows, path-matching escapes, operation-binding or replay
bypasses, digest inconsistencies, and misleading signed/unsigned states are in
scope.
