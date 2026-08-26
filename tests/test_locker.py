from __future__ import annotations

import hashlib
import zipfile

import pytest

from core import locker as locker_mod
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


def test_zip_with_unexpected_member_name_is_rejected(tmp_path):
    zpath = tmp_path / "odd.zip"
    with zipfile.ZipFile(zpath, "w") as zf:
        zf.writestr("seal.json", "{}")
        zf.writestr("artifacts/not-a-hash.txt", "x")

    with pytest.raises(locker_mod.LockerFormatError):
        locker_mod.open_locker(zpath)


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


def test_all_failure_codes_are_registered():
    assert "blob_hash_mismatch" in locker_mod.FAILURE_CODES
    assert "unlisted_blob" in locker_mod.FAILURE_CODES
    assert "key_not_pinned_match" in locker_mod.FAILURE_CODES
