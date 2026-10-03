# Shipcheck — TrustLayer demo agent

A minimal TrustLayer agent that co-signs deliveries (SPEC v0.2.1 §7).
Deploy this folder as its own Vercel project.

## Setup

1. Generate two keys (identity + delivery), on your machine:

   ```bash
   tl keygen YOUR-DOMAIN          # identity key (#key-YYYY-1)
   tl keygen YOUR-DOMAIN          # run again for the delivery key (#delivery-1)
   ```

   Save both seeds in a password manager. **Never commit them.**

2. Serve `/.well-known/did.json` listing **both** keys in
   `verificationMethod` and `assertionMethod` (see `did.json` in this folder
   for the shape).

3. DNS TXT with **both** fingerprints:

   ```
   _trustlayer.YOUR-DOMAIN. 300 IN TXT "v=tl1; fp=sha256:<identity-fp>"
   _trustlayer.YOUR-DOMAIN. 300 IN TXT "v=tl1; fp=sha256:<delivery-fp>"
   ```

4. Create `trustlayer.json` (capability `shipment-status`, endpoint
   `https://YOUR-DOMAIN/v1/run`), sign it with the **identity** key
   (`tl sign --seed-env ...`), and serve it at `/.well-known/trustlayer.json`.

5. In the Vercel project for this folder, set encrypted environment variables:
   - `TL_DELIVERY_SEED` — the delivery key seed (base64url). Never logged.
   - `SHIPCHECK_DOMAIN` — your host.

6. Verify: `tl verify YOUR-DOMAIN` → **L2**.

## Try it

Without a nonce (plain response, no delivery header):

```bash
curl -i "https://YOUR-DOMAIN/v1/run?id=ACME-123"
```

With a nonce (co-signed delivery):

```bash
curl -i "https://YOUR-DOMAIN/v1/run?id=ACME-123" \
  -H "TrustLayer-Nonce: $(python -c 'import secrets,base64;print(base64.urlsafe_b64encode(secrets.token_bytes(16)).rstrip(b"=").decode())')" \
  -H "TrustLayer-Task-Hash: sha256:$(python -c 'import hashlib;print(hashlib.sha256(b"my secret task").hexdigest())')"
```

The response carries `TrustLayer-Delivery` (base64url JSON). You can check it
yourself: `result_hash` is the sha256 of the exact body bytes you received,
and the signature verifies against the `#delivery-1` key in did.json.
