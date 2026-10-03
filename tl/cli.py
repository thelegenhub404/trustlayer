"""TrustLayer CLI: tl keygen | sign | verify | check-domain.

Also serves as a usage example: the same library functions power the crawler
and the API.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import stat
import sys

from . import __version__
from .canon import canonicalize
from .keys import (b64u_encode, fingerprint, generate_keypair, sign, to_jwk)
from .verify import txt_fingerprints, verify_domain


def _emit(obj: object) -> None:
    print(json.dumps(obj, indent=2, ensure_ascii=False))


def cmd_keygen(args: argparse.Namespace) -> int:
    """Generate an Ed25519 keypair and print the pieces needed for did.json."""
    priv, pub = generate_keypair()
    kid = f"did:web:{args.domain}#key-{dt.date.today().year}-1"
    _emit({
        "domain": args.domain,
        "kid": kid,
        "public_key_jwk": to_jwk(pub),
        "dns_txt_record": {
            "name": f"_trustlayer.{args.domain}",
            "type": "TXT",
            "ttl": 300,
            "value": f"v=tl1; fp={fingerprint(pub)}",
        },
        "private_key_seed_b64u": b64u_encode(priv.private_bytes_raw()),
        "note": "Save this seed now; it is shown only this once. Keep it secret: "
                "never commit it, never place it in your web root.",
    })
    return 0


def cmd_sign(args: argparse.Namespace) -> int:
    """Sign a trustlayer.json file (adds the signature field) and print it."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from .keys import b64u_decode

    with open(args.file, encoding="utf-8") as fh:
        card = json.load(fh)
    if "signature" in card:
        del card["signature"]
    seed_source = None
    seed_value = None
    if args.seed_b64u:
        seed_source, seed_value = "argv", args.seed_b64u
        print("warning: the seed was passed on the command line and stays in "
              "your shell history and process list; prefer --seed-env or "
              "--seed-file", file=sys.stderr)
    elif args.seed_env:
        seed_source, seed_value = "env", os.environ.get(args.seed_env, "")
        if not seed_value:
            print(f"error: environment variable {args.seed_env} is empty or "
                  "not set", file=sys.stderr)
            return 2
    elif args.seed_file:
        path = pathlib.Path(args.seed_file)
        if not path.is_file():
            print(f"error: seed file not found: {path}", file=sys.stderr)
            return 2
        if os.name == "posix":
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                print(f"warning: {path} is readable by group/others "
                      f"(mode {oct(mode)}); fix with: chmod 600 {path}",
                      file=sys.stderr)
        seed_source, seed_value = "file", path.read_text(encoding="ascii").strip()
    if seed_source in ("env", "file", "argv"):
        seed = b64u_decode(seed_value)
        priv = Ed25519PrivateKey.from_private_bytes(seed)
    else:
        priv, _ = generate_keypair()
        print("warning: no key given (--seed-env, --seed-file or --seed-b64u); "
              "generated a throwaway key", file=sys.stderr)
    kid = args.kid or (card.get("agent_id") or "") + "#key-1"
    sig = sign(priv, canonicalize(card))
    card["signature"] = {"alg": "Ed25519", "kid": kid, "value": sig}
    _emit(card)
    return 0


def cmd_verify(args: argparse.Namespace) -> int:
    """Run the full verification algorithm against a domain."""
    result = verify_domain(args.domain, fetch_dns=not args.no_dns)
    _emit(result)
    return 0 if result["level"] == "L2" else 1


def cmd_check_domain(args: argparse.Namespace) -> int:
    """Quick check: does TXT _trustlayer.DOMAIN publish any fingerprints?"""
    fps = txt_fingerprints(args.domain)
    _emit({"domain": args.domain, "fingerprints": fps})
    return 0 if fps else 1


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="tl", description="TrustLayer CLI — verify and sign agent identities")
    parser.add_argument("--version", action="version",
                        version=f"trustlayer {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("keygen", help="generate an Ed25519 keypair for a domain")
    p.add_argument("domain", help="agent domain, e.g. analytics.example.com")
    p.set_defaults(func=cmd_keygen)

    p = sub.add_parser("sign", help="sign a trustlayer.json file")
    p.add_argument("file", help="path to trustlayer.json (without signature)")
    p.add_argument("--seed-b64u", help="private key seed, base64url (stays in "
                                        "shell history; prefer --seed-env)")
    p.add_argument("--seed-env", metavar="VAR",
                   help="read the private key seed from this environment variable")
    p.add_argument("--seed-file", metavar="PATH",
                   help="read the private key seed from a file (warns if not 0600)")
    p.add_argument("--kid", help="key id to reference in the signature")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("verify", help="verify a domain (L0-L2)")
    p.add_argument("domain")
    p.add_argument("--no-dns", action="store_true", help="skip the DNS TXT check")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("check-domain", help="list fingerprints in DNS TXT")
    p.add_argument("domain")
    p.set_defaults(func=cmd_check_domain)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
