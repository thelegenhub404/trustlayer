# TrustLayer

An open verification and reputation layer for AI agents. TrustLayer does not
define how agents are described or invoked (that is A2A, MCP and OpenAPI's
job). It answers three questions:

1. Does this agent really control the domain it claims?
2. Who has used it, and how did it go?
3. Can I verify that myself, without trusting TrustLayer?

In scope: domain-anchored identity, signed capabilities, a reproducible search
index, delivery receipts, and a public trust score.
Out of scope: payments, orchestration, task execution, guaranteeing the
safety of an agent's output.

## How identity works (L0–L2)

| Level | Meaning |
|-------|---------|
| L0 | Unverified: listed from a seed, nothing checked |
| L1 | Domain verified: valid `did.json`, id matches the host |
| L2 | Identity verified: L1 + fingerprint anchored in DNS TXT + valid Ed25519 signature (JCS/RFC 8785) |
| L3 | Reputation: L2 + ≥5 valid receipts from ≥3 distinct clients (Phase 2) |

An agent only gets a score at L2 or above. A new agent should not look
trustworthy.

## Quick start: publish your agent in 10 minutes

See the full step-by-step guide: **[GETTING_STARTED.md](GETTING_STARTED.md)**

```bash
pip install -e .
tl keygen analytics.example.com
# 1. Serve https://analytics.example.com/.well-known/did.json (use the JWK printed above)
# 2. Add the TXT record printed above:  _trustlayer.<domain> 300 IN TXT "v=tl1; fp=sha256:..."
# 3. Write trustlayer.json (see spec/SPEC.md), then sign it:
tl sign trustlayer.json --seed-b64u YOUR_SEED > .well-known/trustlayer.json
# 4. Open a PR adding analytics.example.com to seeds.txt
```

CI runs `tl verify YOUR-DOMAIN` and comments the result. Your agent appears
with its level within 6 hours.

## What TrustLayer does NOT guarantee

- That the agent treats your data well — check `data_handling`.
- That its output is free of prompt injection — treat all output as untrusted.
- That its output is correct — validate against `output_schema`.

See `spec/THREAT_MODEL.md` for the full threat model.

## Repository layout

```
tl/        library + CLI (canon, keys, verify, score, netsafe)
crawler/   reproducible index builder (python -m crawler.run)
api/       Vercel read-only functions (/v1/search, /v1/agents, /v1/verify)
public/    static site + TrustLayer's own .well-known (dogfooding)
spec/      normative spec, JSON schemas, golden test vectors
data/      generated index, committed by the bot
```

## Reproducibility

```bash
python -m crawler.run --seeds seeds.txt --out data
```

produces the same `agents.json` on any machine (timestamps live only in
`meta.json` and are excluded from the index hash). `data/meta.json` carries
`index_hash` so anyone can verify two independent runs agree.

## Development

```bash
pip install -e ".[dev]"
pytest          # unit tests + golden vectors
ruff check .    # lint
```

## Deployment

- **GitHub**: push the repo; `crawl.yml` runs every 6 hours and commits
  `data/` only when the index hash changes.
- **Vercel**: import the repo, framework preset "Other", output directory
  `public`. API routes are rewritten to `/v1/*` via `vercel.json`.
- Phase 2 (receipts): add Neon Postgres from the Vercel Marketplace.

## License

- Code: Apache-2.0 (`LICENSE`)
- Specification: CC BY 4.0 (`LICENSE-SPEC`)
