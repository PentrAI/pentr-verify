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
