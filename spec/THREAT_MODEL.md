# Threat Model

## Outbound request safety (SSRF)

`tl/netsafe.py` is the only module that makes outbound requests:
- https only;
- DNS resolved up front; private, loopback, link-local and cloud metadata IPs
  rejected;
- the resolved IP is pinned for the connection (DNS rebinding defense) while
  the hostname is used for SNI/cert verification;
- ≤3 redirects, same host only;
- 256 KB body limit, 10 s timeout;
- identifiable User-Agent with contact URL;
- robots.txt respected for paths outside `.well-known` (enforced by the
  crawler, not the fetch primitive).

## Threats and mitigations

| Threat | Mitigation | Residual risk |
|---|---|---|
| Compromised web server swaps the key | DNS TXT anchor | Attacker also controls DNS |
| Agent impersonates another domain | `id` must equal `did:web:HOST` | Typosquatting: show full domain, warn |
| Endpoint points to a third party | eTLD+1 rule / declared `service` | — |
| Sybil clients | Reputation weight, per-client cap, domain age | Old-domain farms |
| Fabricated success receipts | Require agent signature | Agent–client collusion |
| Slander (fake failure receipts) | Client must be L1, daily cap, reputation weight, agent reply | High-weight clients |
| Agent hides bad receipts | The API is the canonical source | — |
| Prompt injection in descriptions | Indexed text treated as data; escaped HTML; never injected unmarked into prompts | End client must sanitize |
| Receipt replay | Nonce + idempotent receipt_id | — |
| API abuse | Vercel limits + CDN cache | Volumetric DDoS |
| Reidentification via hashes | Task salt | Client loses the salt |

## Security ≠ trust

The score guarantees domain control and historical usage outcomes. It does
**not** guarantee that an agent handles data well, that output is free of
prompt injection, or that output is correct. Every consumer must:
- review `data_handling` before sending sensitive data;
- treat all agent output as untrusted;
- validate output against the capability's `output_schema`.
