from __future__ import annotations

import hashlib
import json

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from core import signing

BLOCK_KWARGS = {
    "chain_head": "c" * 64,
    "manifest_sha256": "m" * 64,
    "key_id": "k" * 64,
    "signed_at": "2026-08-26T12:00:00+00:00",
}


def _keypair():
    priv = signing.generate_private_key()
    return priv, signing.raw_public_key_from_private(priv)


def test_generate_private_key_is_32_raw_bytes():
    priv = signing.generate_private_key()
    assert isinstance(priv, bytes) and len(priv) == 32


def test_raw_public_key_is_32_bytes_and_deterministic():
    priv, pub = _keypair()
    assert len(pub) == 32
    assert signing.raw_public_key_from_private(priv) == pub


def test_key_id_is_sha256_of_public_key():
    _, pub = _keypair()
    assert signing.key_id_for(pub) == hashlib.sha256(pub).hexdigest()
    assert len(signing.key_id_for(pub)) == 64


def test_key_id_differs_per_key():
    _, pub_a = _keypair()
    _, pub_b = _keypair()
    assert signing.key_id_for(pub_a) != signing.key_id_for(pub_b)


def test_signature_block_is_canonical_json():
    block = signing.signature_block(**BLOCK_KWARGS)
    text = block.decode("utf-8")
    assert " " not in text  # no whitespace: separators=(",", ":")
    parsed = json.loads(text)
    assert list(parsed.keys()) == sorted(parsed.keys())
    assert parsed == {
        "algorithm": "ed25519-v1",
        "chain_head": "c" * 64,
        "key_id": "k" * 64,
        "manifest_sha256": "m" * 64,
        "signed_at": "2026-08-26T12:00:00+00:00",
        "version": "pentr-locker-1",
    }


def test_signature_block_is_stable():
    assert signing.signature_block(**BLOCK_KWARGS) == signing.signature_block(**BLOCK_KWARGS)


def test_sign_then_verify_roundtrip():
    priv, pub = _keypair()
    signer = signing.SoftwareSigner(priv, signing.key_id_for(pub))
    assert signer.algorithm == "ed25519-v1"
    assert signer.key_id == signing.key_id_for(pub)
    block = signing.signature_block(**BLOCK_KWARGS)
    sig = signer.sign(block)
    assert len(sig) == 64
    assert signing.verify_signature(pub, block, sig) is True


def test_verify_fails_on_mutated_block():
    priv, pub = _keypair()
    signer = signing.SoftwareSigner(priv, signing.key_id_for(pub))
    block = signing.signature_block(**BLOCK_KWARGS)
    sig = signer.sign(block)
    tampered = bytearray(block)
    tampered[10] ^= 0x01
    assert signing.verify_signature(pub, bytes(tampered), sig) is False


def test_verify_fails_on_different_public_key():
    priv, _ = _keypair()
    _, other_pub = _keypair()
    signer = signing.SoftwareSigner(priv, "k" * 64)
    block = signing.signature_block(**BLOCK_KWARGS)
    assert signing.verify_signature(other_pub, block, signer.sign(block)) is False


def test_verify_fails_on_mutated_signature():
    priv, pub = _keypair()
    signer = signing.SoftwareSigner(priv, "k" * 64)
    block = signing.signature_block(**BLOCK_KWARGS)
    sig = bytearray(signer.sign(block))
    sig[0] ^= 0x01
    assert signing.verify_signature(pub, block, bytes(sig)) is False


def test_verify_returns_false_on_garbage_signature_length():
    _, pub = _keypair()
    assert signing.verify_signature(pub, b"block", b"too-short") is False


def test_verify_returns_false_on_none_signature():
    """run_seals.signature is nullable by design; a verifier reading an old,
    pre-signing seal will call this with signature=None. That must not raise."""
    _, pub = _keypair()
    assert signing.verify_signature(pub, b"block", None) is False


def test_public_key_pem_roundtrips():
    _, pub = _keypair()
    pem = signing.public_key_pem(pub)
    assert pem.startswith("-----BEGIN PUBLIC KEY-----")
    loaded = serialization.load_pem_public_key(pem.encode("utf-8"))
    assert loaded.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ) == pub


def test_private_key_from_pem_accepts_ed25519():
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    raw = signing.private_key_from_pem(pem)
    assert len(raw) == 32
    assert signing.raw_public_key_from_private(raw) == key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )


def test_private_key_from_pem_rejects_rsa():
    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    with pytest.raises(signing.InvalidKeyError):
        signing.private_key_from_pem(pem)


def test_private_key_from_pem_rejects_garbage():
    with pytest.raises(signing.InvalidKeyError):
        signing.private_key_from_pem("not a pem at all")


def test_private_key_from_pem_rejects_encrypted_pem():
    pem = Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(b"hunter2"),
    ).decode("utf-8")
    with pytest.raises(signing.InvalidKeyError):
        signing.private_key_from_pem(pem)
