from __future__ import annotations

import hashlib
import json
import struct
import zipfile

import pytest

from pentr_verify import hash_chain, signing
from pentr_verify import locker as locker_mod
from tests.conftest import _write_dir_locker, _zip_from_dir


def test_open_directory_locker_reads_files(tmp_path):
    blob = b"nmap output"
    sha = hashlib.sha256(blob).hexdigest()
    root = _write_dir_locker(tmp_path / "loc", {"seal.json": b"{}"}, {sha: blob})

    lk = locker_mod.open_locker(root)

    assert lk.read("seal.json") == b"{}"
    assert lk.list_artifact_names() == {sha}
    assert lk.read_artifact(sha) == blob


def test_open_zip_locker_reads_same_content(tmp_path):
    blob = b"nmap output"
    sha = hashlib.sha256(blob).hexdigest()
    root = _write_dir_locker(tmp_path / "loc", {"seal.json": b"{}"}, {sha: blob})
    zpath = _zip_from_dir(root, tmp_path / "loc.zip")

    lk = locker_mod.open_locker(zpath)

    assert lk.read("seal.json") == b"{}"
    assert lk.list_artifact_names() == {sha}
    assert lk.read_artifact(sha) == blob


def test_missing_file_raises_naming_the_file(tmp_path):
    root = _write_dir_locker(tmp_path / "loc", {"seal.json": b"{}"}, {})
    lk = locker_mod.open_locker(root)

    with pytest.raises(locker_mod.LockerFormatError) as exc:
        lk.read("manifest.json")
    assert "manifest.json" in str(exc.value)


def test_nonexistent_path_raises(tmp_path):
    with pytest.raises(locker_mod.LockerFormatError):
        locker_mod.open_locker(tmp_path / "nope")


def test_zip_with_traversal_member_is_rejected(tmp_path):
    zpath = tmp_path / "evil.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("seal.json", "{}")
        zf.writestr("../escape.txt", "pwned")

    with pytest.raises(locker_mod.LockerFormatError):
        locker_mod.open_locker(zpath)


def test_zip_with_unexpected_root_member_name_is_rejected(tmp_path):
    zpath = tmp_path / "odd.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr(locker_mod.SEAL_NAME, "{}")
        zf.writestr("notes.txt", "x")

    with pytest.raises(locker_mod.LockerFormatError):
        locker_mod.open_locker(zpath)


def test_zip_with_nested_artifact_path_is_rejected(tmp_path):
    """No locker writer produces a nested artifacts path, and the directory
    reader cannot see one, so the zip reader refuses it outright."""
    zpath = tmp_path / "nested.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr(locker_mod.SEAL_NAME, "{}")
        zf.writestr("artifacts/sub/thing.txt", "x")

    with pytest.raises(locker_mod.LockerFormatError):
        locker_mod.open_locker(zpath)


def test_smuggled_artifact_is_unlisted_blob_in_both_containers(good_locker, tmp_path):
    """The same tamper must get the same verdict from a directory and a zip.
    A smuggled non-hex blob is evidence-not-sealed (exit 1), never "you gave me
    a broken path" (exit 2) — and export only ever produces the zip form, so
    the zip is the reading auditors actually get."""
    (good_locker / "artifacts" / "secret.txt").write_bytes(b"not sealed")
    zpath = _zip_from_dir(good_locker, tmp_path / "smuggled.zip")

    dir_report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))
    zip_report = locker_mod.verify_locker(locker_mod.open_locker(zpath))

    assert dir_report.to_dict() == zip_report.to_dict()
    assert dir_report.ok is False
    assert [f.code for f in dir_report.failures] == ["unlisted_blob"]
    assert dir_report.failures[0].subject == "secret.txt"


def test_zip_member_over_the_size_cap_is_rejected(tmp_path):
    """A zip bomb: 10 MiB + 1 of zeros deflates to a few KB. The reader must
    refuse it before materialising it, or `pentr-verify` — the one component
    pointed at files from untrusted parties — is a memory-exhaustion primitive."""
    cap = locker_mod.MAX_MEMBER_BYTES
    sha = "a" * 64
    zpath = tmp_path / "bomb.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(locker_mod.SEAL_NAME, "{}")
        zf.writestr(f"artifacts/{sha}", b"\0" * (cap + 1))

    lk = locker_mod.open_locker(zpath)

    with pytest.raises(locker_mod.LockerFormatError) as exc:
        lk.read_artifact(sha)
    message = str(exc.value)
    assert sha in message
    assert str(cap) in message
    assert str(cap + 1) in message


def test_directory_member_over_the_size_cap_is_rejected(tmp_path):
    cap = locker_mod.MAX_MEMBER_BYTES
    sha = "b" * 64
    root = _write_dir_locker(tmp_path / "loc", {locker_mod.SEAL_NAME: b"{}"},
                             {sha: b"\0" * (cap + 1)})

    lk = locker_mod.open_locker(root)

    with pytest.raises(locker_mod.LockerFormatError) as exc:
        lk.read_artifact(sha)
    message = str(exc.value)
    assert sha in message
    assert str(cap) in message
    assert str(cap + 1) in message


def test_zip_member_with_lying_declared_size_is_rejected(tmp_path):
    """The central directory's `file_size` is attacker-controlled, so the
    header check alone is not a guard. Hand-patch it to understate the real
    content and confirm the read still fails as a format error rather than
    escaping as a raw BadZipFile (which the CLI would surface as a traceback)."""
    cap = locker_mod.MAX_MEMBER_BYTES
    sha = "c" * 64
    zpath = tmp_path / "liar.zip"
    with zipfile.ZipFile(zpath, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(locker_mod.SEAL_NAME, "{}")
        zf.writestr(f"artifacts/{sha}", b"\0" * (cap + 1))

    raw = bytearray(zpath.read_bytes())
    # structCentralDir: uncompressed size is a 4-byte LE field at offset 24 of
    # each central-directory header.
    idx = raw.find(b"PK\x01\x02", raw.find(f"artifacts/{sha}".encode()))
    assert idx != -1
    while struct.unpack("<L", raw[idx + 24:idx + 28])[0] != cap + 1:
        idx = raw.find(b"PK\x01\x02", idx + 1)
        assert idx != -1
    raw[idx + 24:idx + 28] = struct.pack("<L", 100)
    zpath.write_bytes(bytes(raw))

    lk = locker_mod.open_locker(zpath)

    with pytest.raises(locker_mod.LockerFormatError):
        lk.read_artifact(sha)


def test_artifact_member_name_with_trailing_newline_is_rejected(tmp_path):
    """`$` also matches just before a trailing newline, so a guard written with
    it accepts a name it was written to reject. The file is really created, so
    the read would otherwise succeed rather than fail as "missing"."""
    smuggled = "d" * 64 + "\n"
    root = _write_dir_locker(tmp_path / "loc", {locker_mod.SEAL_NAME: b"{}"},
                             {smuggled: b"payload"})
    lk = locker_mod.open_locker(root)
    assert (root / "artifacts" / smuggled).is_file()

    with pytest.raises(locker_mod.LockerFormatError) as exc:
        lk.read_artifact(smuggled)
    assert "not a valid locker member" in str(exc.value)


def test_directory_locker_rejects_traversal_members(tmp_path):
    root = _write_dir_locker(tmp_path / "loc", {"seal.json": b"{}"}, {})
    lk = locker_mod.open_locker(root)

    with pytest.raises(locker_mod.LockerFormatError) as exc:
        lk.read("artifacts/../../etc/passwd")
    assert "artifacts/../../etc/passwd" in str(exc.value)


def test_verify_report_to_dict_is_json_serializable():
    import json as _json

    report = locker_mod.VerifyReport(
        ok=False, pinned=True, key_id="ab" * 32, run_id="run-1",
        chain_head="cd" * 32, entry_count=1, signed_at="2026-08-26T00:00:00+00:00",
        entries=[locker_mod.EntryResult(seq=0, sha256="ef" * 32, kind="command_log",
                                        filename=None, ok=False, reason="hash mismatch")],
        failures=[locker_mod.Failure(code="blob_hash_mismatch", message="bad",
                                     subject="ef" * 32)],
    )
    payload = _json.loads(_json.dumps(report.to_dict()))

    assert payload["ok"] is False
    assert payload["pinned"] is True
    assert payload["entries"][0]["seq"] == 0
    assert payload["failures"][0]["code"] == "blob_hash_mismatch"


def test_failure_codes_are_the_frozen_wire_contract():
    """Assert the whole set, not a sample: Phase 5's viewer and any `--json`
    consumer switch on these slugs, so a rename or a drop must break the build."""
    assert locker_mod.FAILURE_CODES == frozenset({
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


def test_failure_rejects_an_unregistered_code():
    """The contract is enforced in production code, not just asserted in a
    test, so an invented code cannot ship silently in `--json` output."""
    with pytest.raises(AssertionError):
        locker_mod.Failure("blob_hash_mismtach", "typo")


def test_good_locker_verifies_unpinned(good_locker, locker_material):
    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is True
    assert report.pinned is False
    assert report.key_id == locker_material["key_id"]
    assert report.chain_head == locker_material["chain_head"]
    assert report.failures == []


def test_good_locker_verifies_pinned(good_locker, locker_material):
    report = locker_mod.verify_locker(
        locker_mod.open_locker(good_locker),
        pinned_public_key=locker_material["public_raw"],
    )

    assert report.ok is True
    assert report.pinned is True


def test_wrong_pinned_key_fails(good_locker):
    other = signing.raw_public_key_from_private(signing.generate_private_key())

    report = locker_mod.verify_locker(
        locker_mod.open_locker(good_locker), pinned_public_key=other
    )

    assert report.ok is False
    assert [f.code for f in report.failures] == ["key_not_pinned_match"]


def test_foreign_public_key_in_locker_fails_key_id(good_locker):
    other_raw = signing.raw_public_key_from_private(signing.generate_private_key())
    (good_locker / "public_key.pem").write_text(signing.public_key_pem(other_raw))

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert [f.code for f in report.failures] == ["key_id_mismatch"]


def test_edited_manifest_fails_binding(good_locker, locker_material):
    doc = json.loads(locker_material["manifest_bytes"])
    doc["run"]["framework"] = "hipaa"
    (good_locker / "manifest.json").write_bytes(json.dumps(doc).encode())

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert [f.code for f in report.failures] == ["manifest_binding_mismatch"]


def test_tampered_signature_fails(good_locker, locker_material):
    bad = bytearray(locker_material["signature"])
    bad[0] ^= 0xFF
    (good_locker / "signature.bin").write_bytes(bytes(bad))

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert [f.code for f in report.failures] == ["signature_invalid"]


def test_unknown_format_fails(good_locker, locker_material):
    seal = dict(locker_material["seal"], format="pentr-locker-99")
    (good_locker / "seal.json").write_bytes(json.dumps(seal).encode())

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert [f.code for f in report.failures] == ["unknown_format"]


def test_unsupported_algorithm_fails(good_locker, locker_material):
    doc = json.loads(locker_material["manifest_bytes"])
    doc["algorithm"] = "merkle-v1"
    (good_locker / "manifest.json").write_bytes(json.dumps(doc).encode())

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert report.failures[0].code == "unsupported_algorithm"


def test_genesis_mismatch_fails(good_locker, locker_material):
    """A manifest spliced from another run: re-sign it so only genesis is wrong."""
    doc = json.loads(locker_material["manifest_bytes"])
    doc["genesis"] = hash_chain.genesis("22222222-2222-2222-2222-222222222222")
    new_bytes = json.dumps(doc, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":")).encode()
    new_sha = hashlib.sha256(new_bytes).hexdigest()
    block = signing.signature_block(
        chain_head=doc["chain_head"], manifest_sha256=new_sha,
        key_id=locker_material["key_id"], signed_at=locker_material["seal"]["signed_at"],
    )
    sig = signing.SoftwareSigner(locker_material["private_raw"],
                                 locker_material["key_id"]).sign(block)
    (good_locker / "manifest.json").write_bytes(new_bytes)
    (good_locker / "signature_block.json").write_bytes(block)
    (good_locker / "signature.bin").write_bytes(sig)
    seal = dict(locker_material["seal"], manifest_sha256=new_sha)
    (good_locker / "seal.json").write_bytes(json.dumps(seal).encode())

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert [f.code for f in report.failures] == ["genesis_mismatch"]


def test_report_lists_every_entry_on_success(good_locker):
    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is True
    assert [e.seq for e in report.entries] == [0, 1]
    assert all(e.ok for e in report.entries)


def test_mutated_blob_byte_fails_naming_the_artifact(good_locker, locker_material):
    sha = next(iter(locker_material["blobs"]))
    original = (good_locker / "artifacts" / sha).read_bytes()
    (good_locker / "artifacts" / sha).write_bytes(original + b"!")

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    codes = {f.code for f in report.failures}
    assert "blob_hash_mismatch" in codes or "blob_size_mismatch" in codes
    assert any(f.subject == sha for f in report.failures)
    assert any(e.sha256 == sha and not e.ok for e in report.entries)


def test_deleted_blob_fails(good_locker, locker_material):
    sha = next(iter(locker_material["blobs"]))
    (good_locker / "artifacts" / sha).unlink()

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert any(f.code == "blob_missing" and f.subject == sha for f in report.failures)


def test_extra_unlisted_blob_fails(good_locker):
    smuggled = b"not sealed"
    sha = hashlib.sha256(smuggled).hexdigest()
    (good_locker / "artifacts" / sha).write_bytes(smuggled)

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert any(f.code == "unlisted_blob" and f.subject == sha for f in report.failures)


def test_edited_chain_head_with_valid_signature_fails(good_locker, locker_material):
    """Re-sign a manifest whose chain_head was edited: only recomputation catches it."""
    doc = json.loads(locker_material["manifest_bytes"])
    doc["chain_head"] = "00" * 32
    new_bytes = json.dumps(doc, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":")).encode()
    new_sha = hashlib.sha256(new_bytes).hexdigest()
    block = signing.signature_block(
        chain_head=doc["chain_head"], manifest_sha256=new_sha,
        key_id=locker_material["key_id"], signed_at=locker_material["seal"]["signed_at"],
    )
    sig = signing.SoftwareSigner(locker_material["private_raw"],
                                 locker_material["key_id"]).sign(block)
    (good_locker / "manifest.json").write_bytes(new_bytes)
    (good_locker / "signature_block.json").write_bytes(block)
    (good_locker / "signature.bin").write_bytes(sig)
    seal = dict(locker_material["seal"], manifest_sha256=new_sha,
                chain_head=doc["chain_head"])
    (good_locker / "seal.json").write_bytes(json.dumps(seal).encode())

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert any(f.code == "chain_head_mismatch" for f in report.failures)


def test_edited_entry_hash_with_valid_signature_fails(good_locker, locker_material):
    """Stage 7's per-entry check is independently reachable: editing one entry's
    stored `entry_hash` does not perturb `compute_chain`, so the recomputed head
    still matches and only `entry_hash_mismatch` catches it. Re-signed with a
    fresh keypair so stages 1-6 genuinely pass."""
    doc = json.loads(locker_material["manifest_bytes"])
    doc["entries"][0]["entry_hash"] = "00" * 32
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

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    codes = [f.code for f in report.failures]
    assert "entry_hash_mismatch" in codes
    # The head still recomputes correctly — this is exactly the case
    # chain_head_mismatch cannot catch.
    assert "chain_head_mismatch" not in codes


def test_seal_claim_disagreeing_with_manifest_fails(good_locker, locker_material):
    seal = dict(locker_material["seal"], entry_count=99)
    (good_locker / "seal.json").write_bytes(json.dumps(seal).encode())

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    assert any(f.code == "seal_claim_mismatch" for f in report.failures)


def test_run_id_is_sourced_from_the_manifest_not_the_unsigned_seal(
        good_locker, locker_material):
    """seal.json is unsigned. On a stage-1-to-6 short-circuit the report must
    still name the run the *signed* manifest describes, not whatever an
    attacker wrote in the header."""
    seal = dict(locker_material["seal"], run_id="not-the-real-run")
    (good_locker / locker_mod.SEAL_NAME).write_bytes(json.dumps(seal).encode())
    bad = bytearray(locker_material["signature"])
    bad[0] ^= 0xFF
    (good_locker / locker_mod.SIGNATURE_NAME).write_bytes(bytes(bad))

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert [f.code for f in report.failures] == ["signature_invalid"]
    assert report.run_id == locker_material["run_id"]


def test_directory_and_zip_produce_identical_reports(good_locker, tmp_path):
    zpath = _zip_from_dir(good_locker, tmp_path / "locker.zip")

    dir_report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))
    zip_report = locker_mod.verify_locker(locker_mod.open_locker(zpath))

    assert dir_report.to_dict() == zip_report.to_dict()


def test_manifest_entry_missing_required_field_raises_format_error(
        malformed_entry_locker):
    """A manifest entry missing a required field is malformed, not tampered:
    the fixture re-signs it so stages 1-6 genuinely pass, and stage 7 must
    reject it with LockerFormatError naming the missing field rather than
    crashing with a bare KeyError."""
    with pytest.raises(locker_mod.LockerFormatError) as exc:
        locker_mod.verify_locker(locker_mod.open_locker(malformed_entry_locker))
    assert "size" in str(exc.value)


def test_size_only_tamper_fails_size_not_hash(good_locker, locker_material):
    """Forging only the manifest's size field (content untouched) must trip
    blob_size_mismatch, not blob_hash_mismatch — a distinct tamper from
    test_mutated_blob_byte_fails_naming_the_artifact, which forges content."""
    sha = next(iter(locker_material["blobs"]))
    doc = json.loads(locker_material["manifest_bytes"])
    for e in doc["entries"]:
        if e["sha256"] == sha:
            e["size"] = e["size"] + 1
    new_bytes = json.dumps(doc, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":")).encode()
    new_sha = hashlib.sha256(new_bytes).hexdigest()
    block = signing.signature_block(
        chain_head=doc["chain_head"], manifest_sha256=new_sha,
        key_id=locker_material["key_id"], signed_at=locker_material["seal"]["signed_at"],
    )
    sig = signing.SoftwareSigner(locker_material["private_raw"],
                                 locker_material["key_id"]).sign(block)
    (good_locker / "manifest.json").write_bytes(new_bytes)
    (good_locker / "signature_block.json").write_bytes(block)
    (good_locker / "signature.bin").write_bytes(sig)
    seal = dict(locker_material["seal"], manifest_sha256=new_sha)
    (good_locker / "seal.json").write_bytes(json.dumps(seal).encode())

    report = locker_mod.verify_locker(locker_mod.open_locker(good_locker))

    assert report.ok is False
    codes = {f.code for f in report.failures}
    assert "blob_size_mismatch" in codes
    assert "blob_hash_mismatch" not in codes
