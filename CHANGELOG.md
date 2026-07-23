# Changelog

## 0.1.1 - 2026-07-23

Post-launch hardening release.

- Fail closed when an action is not a string instead of raising an exception.
- Require nested `scope.channels` and repository `deny_paths` fields at
  runtime, matching the published schema.
- Root-anchor path and ref globs; `*` now stays within one segment and `**`
  provides explicit recursive matching.
- Reject empty and dot path segments.
- Reject duplicate JSON object keys and preserve exact decimal budget values.
- Normalize equivalent decimal spellings in digests; contracts containing
  decimal numbers may therefore have a different digest than 0.1.0.
- Require strict RFC 3339 timestamps and timezone-aware evaluator clocks.
- Preserve a Nostr `created_at` value of zero and reject invalid timestamps.
- Refuse to digest structurally invalid contracts from the CLI.
- Expand regression coverage to 66 unit tests and 24 portable conformance
  cases.

## 0.1.0 - 2026-07-23

Initial experimental public release.
