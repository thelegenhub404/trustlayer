# Publish your agent in 10 minutes

By the end you will have a verified identity at **L2** and an entry in the TrustLayer index. Everything is checked from files on your own domain, and you can repeat every check yourself.

**You need**

- A domain you control, with access to its DNS and to a web server that can serve `/.well-known/` files.
- Python 3.12 or newer and `git`.
- An agent with an HTTPS endpoint (it can be a test endpoint).

You do not need to sign up anywhere. The domain is your identity.

## 1. Install the CLI

```bash
git clone https://github.com/thelegenhub404/trustlayer
cd trustlayer
pip install -e .
tl --help
```

## 2. Create your key

```bash
tl keygen example.com
```

This creates an Ed25519 key pair and prints everything you need for the next steps: the key id (`kid`, e.g. `did:web:example.com#key-2026-1`), the DNS TXT record for step 4, and the private key seed as base64url. Keep the private seed **out of your repo and your web root**. Back it up: if you lose it you must rotate.

## 3. Publish your DID document

Serve this at `https://example.com/.well-known/did.json`, with your public key in the JWK:

```json
{
  "@context": ["https://www.w3.org/ns/did/v1"],
  "id": "did:web:example.com",
  "verificationMethod": [{
    "id": "did:web:example.com#key-2026-1",
    "type": "JsonWebKey2020",
    "controller": "did:web:example.com",
    "publicKeyJwk": { "kty": "OKP", "crv": "Ed25519", "x": "<PUBLIC_KEY_BASE64URL>" }
  }],
  "assertionMethod": ["did:web:example.com#key-2026-1"]
}
```

The `id` must be exactly `did:web:` followed by your host. If it does not match, verification is rejected. Use the `kid` printed by `tl keygen` in both `verificationMethod.id` and `assertionMethod`.

## 4. Anchor the key in DNS

Add the TXT record that `tl keygen` printed:

```
_trustlayer.example.com.  300  IN  TXT  "v=tl1; fp=sha256:<KEY_FINGERPRINT>"
```

This is a second, independent channel. Someone who only controls your web server cannot swap your key.

## 5. Describe your capabilities

Create `trustlayer.json`. Keep it small; link to your schemas by URL.

```json
{
  "spec_version": "trustlayer/0.2",
  "agent_id": "did:web:example.com",
  "name": "My Agent",
  "description": "One sentence about what it does.",
  "version": "1.0.0",
  "contact": "ops@example.com",
  "capabilities": [{
    "id": "my-capability",
    "description": "What it takes and what it returns.",
    "endpoint": "https://example.com/v1/run",
    "protocol": "https+json",
    "payment": { "method": "none" },
    "data_handling": { "retention": "none", "trains_on_inputs": false }
  }],
  "issued_at": "2026-10-03T00:00:00Z",
  "expires_at": "2026-12-01T00:00:00Z"
}
```

Rules that trip people up:

- Endpoints must belong to the same domain as the agent id.
- `expires_at` must be at most 90 days after `issued_at`. Re-sign before it expires.
- `data_handling` is a declaration. TrustLayer does not verify it.

## 6. Sign it

```bash
tl sign trustlayer.json \
  --seed-b64u <PRIVATE_KEY_SEED_BASE64URL> \
  --kid did:web:example.com#key-2026-1 \
  > .well-known/trustlayer.json
```

The signature is computed over the canonical (RFC 8785) form of the file, and `tl sign` writes the signed card to **standard output** — that is why the command redirects it to the file you serve. The `--kid` must be the key id from your `did.json`. Do not edit the file after signing; sign again instead.

Upload the result to `https://example.com/.well-known/trustlayer.json`.

## 7. Check it yourself

```bash
tl verify example.com
```

You should get **L2** with every check passing. If not, see the table below.

| Failing check | Usual cause | Fix |
|---|---|---|
| Id matches the host | Typo, or `www` vs apex | Use the exact host you serve the files from |
| Signature | File changed after signing | Run `tl sign` again |
| Key current | `expires_at` in the past | Re-issue and re-sign |
| DNS anchor | TXT not propagated, wrong fingerprint | Wait for TTL, compare with `tl keygen` output |
| Endpoint domain | Endpoint on another domain | Move it, or declare it as a service in `did.json` |

## 8. Join the index

Open a pull request that adds your domain, one per line, to `seeds.txt`. CI runs the same verification and comments the result. The crawler runs every 6 hours, so your agent appears within one cycle after the merge.

## 9. Show your badge

```markdown
[![TrustLayer](https://snaypy.com/badge/did:web:example.com)](https://snaypy.com/agent/did:web:example.com)
```

The badge shows your level and the date of the last verification, and links to your page. It only proves what that page shows. It does not say your agent is safe or correct.

## Keeping it healthy

- **Re-sign before `expires_at`.** An expired file drops you to L1 until you do.
- **Rotating a key:** publish the new key in `did.json`, add its fingerprint to DNS, sign with it, then remove the old key and list it under `revoked_kids`.
- **Compromise:** remove the DNS record first. Verification fails closed.

## A real example

`snaypy.com` publishes its own files the same way. Compare yours against them:

- https://snaypy.com/.well-known/did.json
- https://snaypy.com/.well-known/trustlayer.json
- https://snaypy.com/agent/did:web:snaypy.com

## Problems

Open an issue at https://github.com/thelegenhub404/trustlayer/issues with the output of `tl verify example.com`.
