from __future__ import annotations

import hashlib
import json
from typing import Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SIGNATURE_VERSION = "pentr-locker-1"
SIGNATURE_ALGORITHM = "ed25519-v1"


class InvalidKeyError(Exception):
    """Raised when key material is unparseable, encrypted, or the wrong algorithm."""


class Signer(Protocol):
    """Produces a detached signature over canonical bytes.

    SEAM — read this before believing any marketing copy: the only implementation
    today is SoftwareSigner, which means the platform holds the org's private key
    (encrypted at rest under PENTR_KEK). That is *software key custody*, not
    "the platform never sees your private key". A KmsSigner or HsmSigner
    implementing this same protocol is the honest upgrade path. It is
    deliberately NOT implemented in Phase 3.
    """

    key_id: str
    algorithm: str

    def sign(self, payload: bytes) -> bytes: ...


class SoftwareSigner:
    """Ed25519 signer over an in-process raw private key."""

    algorithm = SIGNATURE_ALGORITHM

    def __init__(self, private_key_bytes: bytes, key_id: str) -> None:
        self._key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
        self.key_id = key_id

    def sign(self, payload: bytes) -> bytes:
        return self._key.sign(payload)


def _raw_private(key: Ed25519PrivateKey) -> bytes:
    return key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_private_key() -> bytes:
    """Fresh Ed25519 private key as 32 raw bytes."""
    return _raw_private(Ed25519PrivateKey.generate())


def raw_public_key_from_private(private_key_bytes: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(private_key_bytes).public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def private_key_from_pem(pem: str) -> bytes:
    """Parse an unencrypted PKCS#8 Ed25519 private key PEM into 32 raw bytes."""
    try:
        key = serialization.load_pem_private_key(pem.encode("utf-8"), password=None)
    except Exception as exc:
        raise InvalidKeyError(f"unparseable or password-protected PEM: {exc}") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise InvalidKeyError("only Ed25519 private keys are supported")
    return _raw_private(key)


def key_id_for(raw_public_key: bytes) -> str:
    """Derive the key id from the key material itself, so it is self-verifying."""
    return hashlib.sha256(raw_public_key).hexdigest()


def public_key_pem(raw_public_key: bytes) -> str:
    return Ed25519PublicKey.from_public_bytes(raw_public_key).public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def signature_block(*, chain_head: str, manifest_sha256: str, key_id: str,
                    signed_at: str) -> bytes:
    """Canonical bytes that get signed.

    Signing this block rather than the raw manifest binds the key identity and
    the seal time into the signed material: a signature cannot be replayed onto
    another manifest, and a mislabeled key_id is a detected failure rather than
    a confusing one. Serialization rules match core/manifest.py exactly.
    """
    block = {
        "version": SIGNATURE_VERSION,
        "algorithm": SIGNATURE_ALGORITHM,
        "chain_head": chain_head,
        "manifest_sha256": manifest_sha256,
        "key_id": key_id,
        "signed_at": signed_at,
    }
    return json.dumps(
        block, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")


def verify_signature(public_key_bytes: bytes, block_bytes: bytes,
                     signature: bytes) -> bool:
    """Check a detached signature. Returns False on any failure; never raises.

    Phase 4's `pentr verify` is the main consumer; it runs offline against an
    exported locker using this exact function. `run_seals.signature` is
    nullable by design (pre-signing seals have no signature block), so a
    verifier reading an old seal WILL call this with `signature=None` — that
    raises TypeError from the underlying library, not InvalidSignature, so it
    must be caught here too.
    """
    try:
        Ed25519PublicKey.from_public_bytes(public_key_bytes).verify(signature, block_bytes)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
