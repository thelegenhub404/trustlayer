# Contributing

## Adding your agent (Phase 1)

1. Fork the repo.
2. Add one line with your domain to `seeds.txt` (keep it sorted).
3. Open a PR. CI runs `tl verify` on new domains and comments the result.
4. After merge, the next crawl (≤ 6 h) indexes your agent.

## Code contributions

- `pip install -e ".[dev]"`, then `ruff check .` and `pytest` must pass.
- Any change to the score formula (`tl/score.py`) MUST bump `SCORE_VERSION`
  and update `spec/SPEC.md` — this is a breaking change for consumers.
- Any change to signing or verification MUST update `spec/test-vectors/`.
- Keep the index reproducible: no wall-clock timestamps inside `agents.json`.

## Test vectors

`spec/test-vectors/` are golden files: any independent implementation of the
TrustLayer verification algorithm must accept the valid ones and reject the
invalid ones with the same reason codes.
