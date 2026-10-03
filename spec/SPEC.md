# TrustLayer Specification v0.2 (normative)

Status: draft · License: CC BY 4.0

## 1. Identity artifacts

An agent publishes, on its own domain:

1. `https://DOMAIN/.well-known/did.json` — a `did:web` DID document with its
   keys (W3C DID Core; JWK per RFC 8037, `kty: OKP`, `crv: Ed25519`).
2. DNS TXT record `_trustlayer.DOMAIN` — key fingerprints:
   `v=tl1; fp=sha256:HEX` where HEX is SHA-256 over the 32 raw Ed25519 public
   key bytes. Multiple records are allowed for rotation.
3. `https://DOMAIN/.well-known/trustlayer.json` — signed capability card.

### 1.1 trustlayer.json

Required fields: `spec_version` (`trustlayer/0.2`), `agent_id`
(`did:web:HOST`), `name`, `capabilities[]`, `issued_at`, `expires_at`,
`signature{alg, kid, value}`.

- `expires_at` MUST be ≤ 90 days after `issued_at`.
- Each capability: `id`, `description`, `endpoint`, `protocol`
  (`https+json`), `payment.method` (`none` | `api_key` | `http_402`),
  optional `pricing`, optional declarative `data_handling`.
- `revoked_kids[]` (optional) lists retired key ids.

### 1.2 Signature

1. Remove the `signature` field.
2. Canonicalize the remaining JSON with RFC 8785 (JCS).
3. Sign the UTF-8 bytes with Ed25519.
4. Encode the signature as unpadded base64url.

### 1.3 Verification levels

- **L0** listed; nothing verified.
- **L1** `did.json` downloads safely; `id` equals `did:web:HOST` exactly
  (ports encoded `%3A`); `agent_id` matches.
- **L2** L1 + signature valid under the key referenced by `signature.kid`
  (which MUST be Ed25519 and listed in `assertionMethod`) + `now` within
  `[issued_at, expires_at)` + key not in `revoked_kids` + key fingerprint
  present in DNS TXT + endpoints on the same eTLD+1 as the DID (or declared
  as `service` in did.json).
- **L3** L2 + ≥5 valid receipts from ≥3 distinct client eTLD+1s (Phase 2).

A broken signature caps the result at L1. An expired/invalid signature later
drops the agent to L1 and hides the score. Three consecutive unreachable
crawls drop the agent to L0.

## 2. Receipts (Phase 2)

> **v0.2.1 change (agent side, no database required):** the agent signs only
> what it can verify.
>
> - `result_hash` = sha256 of the exact bytes of the response body the agent
>   emits.
> - `task_hash = sha256(salt || JCS(task))` is computed by the client with its
>   private salt and sent in the `TrustLayer-Task-Hash` header; the agent
>   signs it as a commitment of the client, without recomputing it.
> - Delivery = `{"v":1, agent_id, capability_id, nonce, task_hash,
>   result_hash, timestamp, kid}` + `signature` (Ed25519 over the JCS form of
>   the object without `signature`). It travels as base64url(JSON) in the
>   `TrustLayer-Delivery` response header.
> - Optional: without `TrustLayer-Nonce` the agent responds exactly as
>   before.
> - Agents SHOULD use a separate delivery key (`#delivery-1`), distinct from
>   the identity key.
>
> **v0.2.2 — key role separation:** keys have exactly one role.
>
> - The identity key (`#key-*`) appears only in `assertionMethod`; it signs
>   `trustlayer.json`. A card signed by any other key is rejected.
> - The delivery key (`#delivery-*`) appears only in `authentication`; it
>   signs `TrustLayer-Delivery` objects. A delivery signed by any other key
>   is rejected.
> - The DNS TXT record carries the fingerprints of both keys.
> - **Rotating the delivery key** never touches the identity: publish the new
>   delivery key in `did.json` under `authentication`, add its fingerprint to
>   the DNS TXT, start signing with it, then remove the old key and list it
>   under `revoked_kids` in `trustlayer.json`. The identity key, the signed
>   card and the trust level are unaffected.
> - Server-side validation, only when `TrustLayer-Nonce` is present: nonce is
>   16-64 base64url characters; `task_hash` matches `sha256:<64 hex>`;
>   violations return 400 with a clear message.

Co-signed delivery: the client sends a random `nonce` header
(`TrustLayer-Nonce`); the agent returns `TrustLayer-Delivery`: a signed object
with `agent_id`, `capability_id`, `nonce`, `task_hash`, `result_hash`,
`timestamp`. `task_hash = sha256(salt || JCS(task))`; the salt is client-held.

Receipt acceptance rules:
- Client must be L1 or higher.
- `outcome: success` requires a valid `delivery.agent_signature`.
- `failure | timeout | invalid_output` are accepted unilaterally.
- Timestamp within ±24 h of the server; nonce never repeated per
  (client, agent).
- Max 100 receipts per client per agent per day.
- `receipt_id = sha256(JCS(receipt without signatures))` (idempotent).
- Agents may publish a signed reply; receipts are never removed.

## 3. Trust score — `score/1`

Only computed for L2+. Two numbers: `trust` and `confidence`.

Per-receipt weight:
`w = w_client × w_age × w_cap` where
- `w_client`: client reputation (EigenTrust-lite over the client→agent graph,
  seeded from `seeds-trusted.txt`); floor 0.05; if no reputation, base from
  RDAP domain age: <30d → 0.05, <1y → 0.15, else 0.30;
- `w_age = 0.5^(days/90)`;
- `w_cap = 1/sqrt(n)` over the client's previous receipts for the same agent.

Agent reputation: `rep = (S + 2.5) / (N + 5)` where `S` = summed weight of
success receipts, `N` = summed weight of all receipts (prior beta(2.5, 2.5),
empty → 0.5). `confidence = 1 − exp(−N/20)`.

Additional rules:
- >60% of weight from a single client eTLD+1 → `concentration_flag` and that
  client is capped at 30% of total weight.
- Invalid-signature receipts are discarded and logged, never penalizing the
  agent.
- Liveness probes are informational only.

Changing this formula requires a PR and a `SCORE_VERSION` bump.

## 4. API contract

All responses carry `schema: "trustlayer.api/1"`, `index_generated_at`,
`score_version`. Errors: `{"error": {"code": "...", "message": "..."}}`.
CORS `*` on GET. `Cache-Control: public, s-maxage=300`.

- `GET /v1/search?q&min_level&min_trust&min_confidence&capability&limit&offset`
  — BM25; relevance first, level breaks ties.
- `GET /v1/agents/{did}` — full record.
- `GET /v1/verify?agent_id=` — precomputed `{level, checks[], red_flags[], verified_at}`.
- `GET /v1/index/meta` — index hash and versions.
- Phase 2: `POST /v1/receipts`, `GET /v1/agents/{did}/receipts`,
  `POST /v1/receipts/{id}/reply`.

Publishing an agent (Phase 1) = PR to `seeds.txt`; CI runs `tl verify`.
