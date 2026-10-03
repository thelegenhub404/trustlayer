# Golden test vectors

Each vector is a JSON file with:
- `did_doc`: the did.json content;
- `card`: the trustlayer.json content (possibly broken on purpose);
- `expected_level`: L0/L1/L2;
- `expected_reasons`: reason codes that MUST appear among failed checks.

Any independent implementation of the TrustLayer verification algorithm must
accept the valid vectors and reject the invalid ones with the same reason
codes. The canonicalization vectors (`canon-*.json`) are byte-exact: the
canonical form of `input` MUST equal `canonical` exactly.

Generate fresh valid fixtures with:

```bash
python -m tests.vectors --regen
```
