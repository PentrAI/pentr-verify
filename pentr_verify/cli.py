"""`pentr-verify` — verify an exported Pentr evidence locker, offline.

This command needs no network, no database, and no Pentr credentials. It is the
whole point of the evidence locker: an auditor who has never heard of us can
check the evidence with the same code that sealed it.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.locker import LockerFormatError, VerifyReport, open_locker, verify_locker

EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2

_UNPINNED_WARNING = """
UNPINNED: this locker was verified against the public key inside it. That proves
the locker is internally consistent and unmodified since it was signed — it does
NOT prove who signed it. To prove provenance, obtain the organization's public
key through a channel you trust and re-run with --key <file>.
""".strip()


def load_public_key_file(path: str) -> bytes:
    """Read a public key as PEM, 64 hex chars, or 32 raw bytes -> raw 32 bytes."""
    raw = Path(path).read_bytes()
    text = raw.strip()
    if text.startswith(b"-----BEGIN"):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        key = serialization.load_pem_public_key(text)
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError("only Ed25519 public keys are supported")
        return key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    if len(text) == 64:
        try:
            return bytes.fromhex(text.decode("ascii"))
        except (ValueError, UnicodeDecodeError):
            pass
    if len(raw) == 32:
        return raw
    raise ValueError(f"{path} is not an Ed25519 public key (PEM, 64 hex, or 32 bytes)")


def render_text(report: VerifyReport, quiet: bool = False) -> str:
    lines: list[str] = []
    if not quiet:
        for e in report.entries:
            status = "OK  " if e.ok else "BAD "
            name = e.filename or "-"
            lines.append(f"{status} {e.seq:>4}  {e.kind:<16} {e.sha256[:12]}  {name}")
        if report.entries:
            lines.append("")

    if report.ok:
        lines.append("PASS — evidence locker verified")
    else:
        lines.append("FAIL — evidence locker did NOT verify")
        for f in report.failures:
            subject = f" [{f.subject}]" if f.subject else ""
            lines.append(f"  FAIL {f.code}{subject}: {f.message}")

    lines.append("")
    lines.append(
        f"  run          {report.run_id}\n"
        f"  artifacts    {report.entry_count}\n"
        f"  chain head   {report.chain_head}\n"
        f"  signed by    {report.key_id}\n"
        f"  signed at    {report.signed_at}"
    )
    if report.ok and not report.pinned:
        lines.append("")
        lines.append(_UNPINNED_WARNING)
    return "\n".join(lines)


def run(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pentr-verify",
        description="Verify an exported Pentr evidence locker offline.",
    )
    parser.add_argument("locker", help="Path to a locker directory or .zip")
    parser.add_argument("--key", default=None,
                        help="Public key to pin (PEM, hex, or raw). Without it, "
                             "verification proves consistency but not provenance.")
    parser.add_argument("--json", action="store_true", dest="as_json",
                        help="Emit the verification report as JSON")
    parser.add_argument("--quiet", action="store_true",
                        help="Suppress the per-artifact listing")
    args = parser.parse_args(argv)

    pinned: bytes | None = None
    if args.key is not None:
        try:
            pinned = load_public_key_file(args.key)
        except (OSError, ValueError) as exc:
            print(f"pentr-verify: cannot read --key: {exc}", file=sys.stderr)
            return EXIT_USAGE

    try:
        locker = open_locker(args.locker)
        report = verify_locker(locker, pinned_public_key=pinned)
    except LockerFormatError as exc:
        # Not a verification failure: the input is not a locker at all. Reporting
        # this as exit 1 would tell an auditor their evidence was tampered with
        # when they actually just mistyped a path.
        print(f"pentr-verify: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.as_json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render_text(report, quiet=args.quiet))
    return EXIT_PASS if report.ok else EXIT_FAIL


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
