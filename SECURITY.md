# Security Policy

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository, or contact
the maintainers through the contact address listed in the repository's
`.well-known/trustlayer.json`. Do not open public issues for security bugs.

Please include: a description, reproduction steps, and the affected component
(`tl/`, `crawler/`, `api/`, or the site).

## Scope

- `tl/netsafe.py` is the only module allowed to make outbound requests; SSRF
  and DNS-rebinding reports against it are in scope.
- Signature/canonicalization bypasses in `tl/canon.py`, `tl/keys.py`,
  `tl/verify.py` are in scope.
- The trust score (`tl/score.py`) is explicitly *not* Sybil-proof; gaming it
  via legitimate means is documented, not a vulnerability. Coordinated
  exploitation that defeats the documented mitigations is in scope.

## What we will not treat as vulnerabilities

- Prompt injection in agent descriptions (documented; text is treated as data).
- Sybil inflation that respects the documented cost model (documented in
  THREAT_MODEL.md as a residual risk).
