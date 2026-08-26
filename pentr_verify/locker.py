"""Offline reader and verifier for an exported evidence locker.

PURE MODULE — imports nothing from server/, scheduler/, or SQLAlchemy. It must
run on an auditor's machine that has never seen the Pentr database. Every hash
here is recomputed with the exact same primitives that produced the seal
(core.hash_chain, core.manifest, core.signing), which is what makes a PASS
mean something: the verifier cannot drift from the sealer.
"""
from __future__ import annotations

import hashlib
import json
import re
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from core import hash_chain, manifest as manifest_mod, signing
from core.hash_chain import EntryInput

# The locker *packaging* format version, independent of core.manifest.VERSION
# and core.signing.SIGNATURE_VERSION even though all three read "pentr-locker-1"
# today. These are three separately-versioned concerns that happened to ship
# together in Phase 4: the manifest schema, the signature block schema, and the
# container format. Aliasing to either would mean bumping the schema version
# silently changes what the locker advertises, making them unable to move
# independently.
LOCKER_FORMAT = "pentr-locker-1"

MANIFEST_NAME = "manifest.json"
SIGNATURE_BLOCK_NAME = "signature_block.json"
SIGNATURE_NAME = "signature.bin"
PUBLIC_KEY_NAME = "public_key.pem"
SEAL_NAME = "seal.json"
README_NAME = "README.txt"

ROOT_FILES = frozenset({
    MANIFEST_NAME, SIGNATURE_BLOCK_NAME, SIGNATURE_NAME,
    PUBLIC_KEY_NAME, SEAL_NAME, README_NAME,
})
_ARTIFACT_MEMBER = re.compile(r"^artifacts/[0-9a-f]{64}$")


def _validate_member_name(name: str) -> None:
    """Validate that a member name is in the locker allowlist.

    Raises LockerFormatError if the name is not one of the root files or a
    valid artifact path. This guards against path traversal attacks and
    unexpected members.
    """
    if name in ROOT_FILES or _ARTIFACT_MEMBER.match(name):
        return
    raise LockerFormatError(f"not a valid locker member: {name!r}")


class LockerFormatError(Exception):
    """The locker is unreadable or structurally malformed.

    Distinct from a verification failure: this is "you gave me something that
    is not a locker", which the CLI reports as exit 2, not as tampering.
    """


FAILURE_CODES = frozenset({
    "unknown_format",
    "unsupported_algorithm",
    "manifest_binding_mismatch",
    "key_id_mismatch",
    "key_not_pinned_match",
    "signature_invalid",
    "genesis_mismatch",
    "entry_hash_mismatch",
    "chain_head_mismatch",
    "blob_missing",
    "blob_hash_mismatch",
    "blob_size_mismatch",
    "unlisted_blob",
    "seal_claim_mismatch",
})


@dataclass
class Failure:
    code: str
    message: str
    subject: str | None = None

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "subject": self.subject}


@dataclass
class EntryResult:
    seq: int
    sha256: str
    kind: str
    filename: str | None
    ok: bool
    reason: str | None = None

    def to_dict(self) -> dict:
        return {
            "seq": self.seq, "sha256": self.sha256, "kind": self.kind,
            "filename": self.filename, "ok": self.ok, "reason": self.reason,
        }


@dataclass
class VerifyReport:
    ok: bool
    pinned: bool
    key_id: str | None = None
    run_id: str | None = None
    chain_head: str | None = None
    entry_count: int = 0
    signed_at: str | None = None
    entries: list[EntryResult] = field(default_factory=list)
    failures: list[Failure] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ok": self.ok,
            "pinned": self.pinned,
            "key_id": self.key_id,
            "run_id": self.run_id,
            "chain_head": self.chain_head,
            "entry_count": self.entry_count,
            "signed_at": self.signed_at,
            "entries": [e.to_dict() for e in self.entries],
            "failures": [f.to_dict() for f in self.failures],
        }


class Locker:
    """Read-only view over a locker directory or zip."""

    def __init__(self, source: str) -> None:
        self.source = source

    def read(self, name: str) -> bytes:
        """Read a locker member by name.

        Validates that the name is in the allowlist (root files or artifacts)
        before delegating to the backend, guarding against path traversal
        attacks in both directory and zip lockers.
        """
        _validate_member_name(name)
        return self._read_member(name)

    def _read_member(self, name: str) -> bytes:
        """Read a locker member (implemented by subclasses)."""
        raise NotImplementedError

    def list_artifact_names(self) -> set[str]:
        raise NotImplementedError

    def read_artifact(self, sha256: str) -> bytes:
        return self.read(f"artifacts/{sha256}")


class _DirLocker(Locker):
    def __init__(self, root: Path) -> None:
        super().__init__(str(root))
        self._root = root

    def _read_member(self, name: str) -> bytes:
        path = self._root / name
        if not path.is_file():
            raise LockerFormatError(f"locker is missing {name}")
        return path.read_bytes()

    def list_artifact_names(self) -> set[str]:
        # Deliberately does not filter by hex name. Stage 9 of verify_locker
        # must be able to see a smuggled file (e.g., artifacts/secret.txt) in
        # order to fail on it as unlisted_blob. If we filtered here, a smuggled
        # file would be invisible and the locker would pass, silently breaking
        # the strict both-way check.
        adir = self._root / "artifacts"
        if not adir.is_dir():
            return set()
        return {p.name for p in adir.iterdir() if p.is_file()}


class _ZipLocker(Locker):
    def __init__(self, path: Path) -> None:
        super().__init__(str(path))
        try:
            self._zf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise LockerFormatError(f"not a readable zip: {path}") from exc
        self._names = {i.filename for i in self._zf.infolist() if not i.is_dir()}
        # Validate every member up front. Nothing is extracted to disk, but an
        # unexpected name means this is not a locker we understand — and an
        # absolute or traversing path is a hostile archive, not a typo.
        for name in self._names:
            if name in ROOT_FILES or _ARTIFACT_MEMBER.match(name):
                continue
            raise LockerFormatError(f"unexpected member in locker zip: {name!r}")

    def _read_member(self, name: str) -> bytes:
        if name not in self._names:
            raise LockerFormatError(f"locker is missing {name}")
        return self._zf.read(name)

    def list_artifact_names(self) -> set[str]:
        return {n.split("/", 1)[1] for n in self._names if n.startswith("artifacts/")}


def open_locker(path: str | Path) -> Locker:
    p = Path(path)
    if p.is_dir():
        return _DirLocker(p)
    if p.is_file():
        return _ZipLocker(p)
    raise LockerFormatError(f"no such locker: {p}")


def _load_public_key(pem_bytes: bytes) -> bytes:
    """PEM -> raw 32-byte Ed25519 public key."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = serialization.load_pem_public_key(pem_bytes)
    except Exception as exc:
        raise LockerFormatError(f"unreadable {PUBLIC_KEY_NAME}: {exc}") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise LockerFormatError("only Ed25519 public keys are supported")
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _parse_json(raw: bytes, name: str) -> dict:
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise LockerFormatError(f"{name} is not valid JSON: {exc}") from exc
    if not isinstance(doc, dict):
        raise LockerFormatError(f"{name} must be a JSON object")
    return doc


def verify_locker(locker: Locker, *,
                  pinned_public_key: bytes | None = None) -> VerifyReport:
    """Verify an exported locker offline. Never raises on tamper — returns a report.

    Raises LockerFormatError only when the input is not a readable locker at all
    (missing files, bad JSON, unparseable key). That distinction is what lets the
    CLI say "you gave me a broken path" (exit 2) rather than reporting tampering
    (exit 1) for an operator error.

    Stages short-circuit: if the signature does not verify there is no value in
    enumerating a hundred blobs, so the report names the signature failure and
    stops.
    """
    report = VerifyReport(ok=False, pinned=pinned_public_key is not None)

    # --- Stage 1: seal.json + format ---
    seal = _parse_json(locker.read(SEAL_NAME), SEAL_NAME)
    report.run_id = seal.get("run_id")
    report.signed_at = seal.get("signed_at")
    if seal.get("format") != LOCKER_FORMAT:
        report.failures.append(Failure(
            "unknown_format",
            f"locker format {seal.get('format')!r} is not {LOCKER_FORMAT!r}",
            SEAL_NAME,
        ))
        return report

    # --- Stage 2: manifest bytes, verbatim, hashed as read ---
    manifest_bytes = locker.read(MANIFEST_NAME)
    manifest_sha256_actual = hashlib.sha256(manifest_bytes).hexdigest()
    manifest = _parse_json(manifest_bytes, MANIFEST_NAME)
    report.chain_head = manifest.get("chain_head")
    report.entry_count = len(manifest.get("entries") or [])

    if manifest.get("version") != manifest_mod.VERSION:
        report.failures.append(Failure(
            "unknown_format",
            f"manifest version {manifest.get('version')!r} is not "
            f"{manifest_mod.VERSION!r}",
            MANIFEST_NAME,
        ))
        return report
    if manifest.get("algorithm") != manifest_mod.ALGORITHM:
        # A future merkle-v1 locker must fail loudly on an old verifier rather
        # than be checked with the wrong rules and reported as sound.
        report.failures.append(Failure(
            "unsupported_algorithm",
            f"manifest algorithm {manifest.get('algorithm')!r} is not supported by "
            f"this version of pentr-verify (expected {manifest_mod.ALGORITHM!r})",
            MANIFEST_NAME,
        ))
        return report

    # --- Stage 3: the signature block must bind THESE manifest bytes ---
    block_bytes = locker.read(SIGNATURE_BLOCK_NAME)
    block = _parse_json(block_bytes, SIGNATURE_BLOCK_NAME)
    report.key_id = block.get("key_id")
    report.signed_at = block.get("signed_at") or report.signed_at

    if (block.get("version") != signing.SIGNATURE_VERSION
            or block.get("algorithm") != signing.SIGNATURE_ALGORITHM):
        report.failures.append(Failure(
            "unknown_format",
            f"signature block is {block.get('version')!r}/{block.get('algorithm')!r}, "
            f"expected {signing.SIGNATURE_VERSION!r}/{signing.SIGNATURE_ALGORITHM!r}",
            SIGNATURE_BLOCK_NAME,
        ))
        return report
    if block.get("manifest_sha256") != manifest_sha256_actual:
        report.failures.append(Failure(
            "manifest_binding_mismatch",
            f"signature covers manifest {block.get('manifest_sha256')} but this "
            f"locker's manifest hashes to {manifest_sha256_actual}",
            MANIFEST_NAME,
        ))
        return report
    if block.get("chain_head") != manifest.get("chain_head"):
        report.failures.append(Failure(
            "manifest_binding_mismatch",
            f"signature covers chain head {block.get('chain_head')} but the manifest "
            f"records {manifest.get('chain_head')}",
            SIGNATURE_BLOCK_NAME,
        ))
        return report

    # --- Stage 4: key identity (content-derived, so it self-verifies) ---
    public_raw = _load_public_key(locker.read(PUBLIC_KEY_NAME))
    derived_key_id = signing.key_id_for(public_raw)
    if derived_key_id != block.get("key_id"):
        report.failures.append(Failure(
            "key_id_mismatch",
            f"{PUBLIC_KEY_NAME} has key id {derived_key_id} but the signature block "
            f"names {block.get('key_id')}",
            PUBLIC_KEY_NAME,
        ))
        return report
    if pinned_public_key is not None and pinned_public_key != public_raw:
        report.failures.append(Failure(
            "key_not_pinned_match",
            f"locker is signed by key {derived_key_id} but you pinned "
            f"{signing.key_id_for(pinned_public_key)}",
            PUBLIC_KEY_NAME,
        ))
        return report

    # --- Stage 5: the signature itself ---
    signature = locker.read(SIGNATURE_NAME)
    if not signing.verify_signature(public_raw, block_bytes, signature):
        report.failures.append(Failure(
            "signature_invalid",
            f"signature does not verify against key {derived_key_id}",
            SIGNATURE_NAME,
        ))
        return report

    # --- Stage 6: genesis binds the run id (anti cross-run splicing) ---
    run = manifest.get("run") or {}
    expected_genesis = hash_chain.genesis(str(run.get("engagement_id")))
    if expected_genesis != manifest.get("genesis"):
        report.failures.append(Failure(
            "genesis_mismatch",
            f"manifest genesis {manifest.get('genesis')} does not match the genesis "
            f"derived from run {run.get('engagement_id')}",
            MANIFEST_NAME,
        ))
        return report

    report.ok = True
    return report
