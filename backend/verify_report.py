"""Verify a FORENSIX PDF's detached Ed25519 signature.

Usage: python verify_report.py report.pdf --signature report.pdf.sig --public-key keys/ed25519-public.pem
"""

from __future__ import annotations

import argparse
from pathlib import Path

from app.report_signing import verify_report


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify a FORENSIX report signature")
    parser.add_argument("report", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--public-key", type=Path, required=True)
    args = parser.parse_args()
    signature = args.signature or args.report.with_name(f"{args.report.name}.sig")
    try:
        fingerprint = verify_report(args.report, signature, args.public_key)
    except Exception as exc:
        print(f"INVALID: {exc}")
        return 1
    print(f"VALID Ed25519 signature\npublic-key-fingerprint: {fingerprint}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
