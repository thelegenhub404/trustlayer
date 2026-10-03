"""Crawler entry point: python -m crawler.run --seeds seeds.txt --out data

Orchestrates: seeds -> crawl (did.json + trustlayer.json + DNS) -> verify ->
score -> build_index -> write data/ (only when content changed).

Phase 2 will merge a signed receipts dump into the score step.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys

from .build_index import build_agent_record, build_index, write_data
from .discover import load_seeds
from tl.verify import verify_domain


def crawl_domain(domain: str, *, fetch_dns: bool = True) -> tuple[dict, dict | None]:
    """Verify a domain and, when possible, fetch its trustlayer.json card."""
    verification = verify_domain(domain, fetch_dns=fetch_dns)
    card = None
    if verification["level"] in ("L1", "L2"):
        from tl import netsafe
        try:
            status, card, _ = netsafe.fetch_json(
                f"https://{domain}/.well-known/trustlayer.json")
            if status != 200:
                card = None
        except netsafe.SafeFetchError:
            card = None
    return verification, card


def run(seeds_path: str, out_dir: str, *, fetch_dns: bool = True) -> int:
    seeds = load_seeds(seeds_path)
    records = []
    failures = 0
    for domain in seeds:
        try:
            verification, card = crawl_domain(domain, fetch_dns=fetch_dns)
        except Exception as exc:  # never let one domain kill the whole crawl
            print(f"[error] {domain}: {exc}", file=sys.stderr)
            verification = {"level": "L0", "checks": [{"name": "crawl", "ok": False,
                                                       "reason": str(exc)}],
                            "red_flags": []}
            card = None
            failures += 1
        # Phase 1: no receipts yet -> no score for anyone.
        score = None
        records.append(build_agent_record(domain, verification, card, score))
    payload = build_index(records)
    changed = write_data(payload, out_dir, generated_at=dt.datetime.now(
        dt.timezone.utc).isoformat(timespec="seconds"))
    print(json.dumps({
        "n_seeds": len(seeds),
        "n_failures": failures,
        "index_hash": payload["index_hash"],
        "changed": changed,
    }, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m crawler.run")
    parser.add_argument("--seeds", default="seeds.txt")
    parser.add_argument("--out", default="data")
    parser.add_argument("--no-dns", action="store_true",
                        help="skip DNS TXT checks (for offline/dry runs)")
    args = parser.parse_args(argv)
    return run(args.seeds, args.out, fetch_dns=not args.no_dns)


if __name__ == "__main__":
    raise SystemExit(main())
