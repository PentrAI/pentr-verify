from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from pentr_verify import locker as locker_mod
from pentr_verify import manifest as manifest_mod
from pentr_verify import signing
from pentr_verify.hash_chain import EntryInput


def _write_dir_locker(root: Path, files: dict[str, bytes],
                      artifacts: dict[str, bytes]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (root / name).write_bytes(data)
    (root / "artifacts").mkdir(exist_ok=True)
    for sha, data in artifacts.items():
        (root / "artifacts" / sha).write_bytes(data)
    return root


def _zip_from_dir(src: Path, dest: Path) -> Path:
    with zipfile.ZipFile(dest, "w", zipfile.ZIP_DEFLATED) as zf:
        for path in sorted(src.rglob("*")):
            if path.is_file():
                zf.write(path, path.relative_to(src).as_posix())
    return dest


@pytest.fixture
def locker_material():
    """Build a real sealed run's bytes using the same primitives the platform seal uses."""
    run_id = "11111111-1111-1111-1111-111111111111"
    blobs = {}
    entries = []
    for seq, (kind, data) in enumerate([
        ("command_log", b"nmap -sV 10.0.0.5"),
        ("req_resp", b"GET /login HTTP/1.1"),
    ]):
        sha = hashlib.sha256(data).hexdigest()
        blobs[sha] = data
        entries.append(EntryInput(
            seq=seq, kind=kind, phase="intelligence", size=len(data), sha256=sha,
            control_ids=[], finding_ids=[], filename=None,
            created_at="2026-08-26T00:00:0%d+00:00" % seq,
        ))

    manifest_bytes, manifest_sha256 = manifest_mod.build_manifest(
        run_id=run_id, engagement_id=run_id, framework="soc2",
        scope_in=["10.0.0.0/24"], scope_out=[], rules={"max_duration_minutes": 60},
        started_at="2026-08-26T00:00:00+00:00", ended_at="2026-08-26T01:00:00+00:00",
        entries=entries,
    )
    chain_head = json.loads(manifest_bytes)["chain_head"]

    private_raw = signing.generate_private_key()
    public_raw = signing.raw_public_key_from_private(private_raw)
    key_id = signing.key_id_for(public_raw)
    signed_at = "2026-08-26T01:00:00+00:00"
    block_bytes = signing.signature_block(
        chain_head=chain_head, manifest_sha256=manifest_sha256,
        key_id=key_id, signed_at=signed_at,
    )
    signature = signing.SoftwareSigner(private_raw, key_id).sign(block_bytes)

    seal = {
        "format": locker_mod.LOCKER_FORMAT,
        "run_id": run_id,
        "chain_head": chain_head,
        "manifest_sha256": manifest_sha256,
        "entry_count": len(entries),
        "algorithm": manifest_mod.ALGORITHM,
        "signature_algorithm": signing.SIGNATURE_ALGORITHM,
        "signing_key_id": key_id,
        "signed_at": signed_at,
        "sealed_at": signed_at,
        "exported_at": "2026-08-26T02:00:00+00:00",
    }
    return {
        "run_id": run_id, "blobs": blobs, "manifest_bytes": manifest_bytes,
        "manifest_sha256": manifest_sha256, "chain_head": chain_head,
        "block_bytes": block_bytes, "signature": signature,
        "public_raw": public_raw, "private_raw": private_raw, "key_id": key_id,
        "seal": seal,
    }


@pytest.fixture
def good_locker(tmp_path, locker_material):
    m = locker_material
    root = _write_dir_locker(
        tmp_path / "locker",
        {
            locker_mod.MANIFEST_NAME: m["manifest_bytes"],
            locker_mod.SIGNATURE_BLOCK_NAME: m["block_bytes"],
            locker_mod.SIGNATURE_NAME: m["signature"],
            locker_mod.PUBLIC_KEY_NAME:
                signing.public_key_pem(m["public_raw"]).encode(),
            locker_mod.SEAL_NAME: json.dumps(m["seal"]).encode(),
            locker_mod.README_NAME: b"run pentr-verify",
        },
        m["blobs"],
    )
    return root


@pytest.fixture
def malformed_entry_locker(good_locker, locker_material):
    """A locker that opens cleanly and passes stages 1-6, then trips stage 7's
    required-field check. Re-signed with a fresh keypair so nothing before
    stage 7 can be what fails: this is the only shape that exercises a
    LockerFormatError raised by verify_locker rather than by open_locker."""
    doc = json.loads(locker_material["manifest_bytes"])
    del doc["entries"][0]["size"]
    new_bytes = json.dumps(doc, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":")).encode()
    new_sha = hashlib.sha256(new_bytes).hexdigest()

    private_raw = signing.generate_private_key()
    public_raw = signing.raw_public_key_from_private(private_raw)
    key_id = signing.key_id_for(public_raw)
    block = signing.signature_block(
        chain_head=doc["chain_head"], manifest_sha256=new_sha, key_id=key_id,
        signed_at=locker_material["seal"]["signed_at"],
    )
    sig = signing.SoftwareSigner(private_raw, key_id).sign(block)

    (good_locker / locker_mod.MANIFEST_NAME).write_bytes(new_bytes)
    (good_locker / locker_mod.SIGNATURE_BLOCK_NAME).write_bytes(block)
    (good_locker / locker_mod.SIGNATURE_NAME).write_bytes(sig)
    (good_locker / locker_mod.PUBLIC_KEY_NAME).write_text(
        signing.public_key_pem(public_raw))
    seal = dict(locker_material["seal"], manifest_sha256=new_sha,
                signing_key_id=key_id)
    (good_locker / locker_mod.SEAL_NAME).write_bytes(json.dumps(seal).encode())
    return good_locker
