from __future__ import annotations

import json

from core import signing
from verify import cli


def test_good_locker_exits_zero(good_locker, capsys):
    code = cli.run([str(good_locker)])

    assert code == 0
    out = capsys.readouterr().out
    assert "PASS" in out


def test_unpinned_run_warns_about_provenance(good_locker, capsys):
    cli.run([str(good_locker)])

    out = capsys.readouterr().out
    assert "UNPINNED" in out
    assert "--key" in out


def test_pinned_run_does_not_warn(good_locker, locker_material, tmp_path, capsys):
    keyfile = tmp_path / "org.pem"
    keyfile.write_text(signing.public_key_pem(locker_material["public_raw"]))

    code = cli.run([str(good_locker), "--key", str(keyfile)])

    assert code == 0
    assert "UNPINNED" not in capsys.readouterr().out


def test_tampered_locker_exits_one(good_locker, locker_material, capsys):
    sha = next(iter(locker_material["blobs"]))
    (good_locker / "artifacts" / sha).write_bytes(b"tampered")

    code = cli.run([str(good_locker)])

    assert code == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert sha in out


def test_nonexistent_path_exits_two(tmp_path, capsys):
    code = cli.run([str(tmp_path / "nope")])

    assert code == 2


def test_json_output_shape(good_locker, capsys):
    code = cli.run([str(good_locker), "--json"])

    assert code == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["pinned"] is False
    assert len(payload["entries"]) == 2
    assert payload["failures"] == []


def test_quiet_suppresses_per_artifact_lines(good_locker, capsys):
    cli.run([str(good_locker), "--quiet"])

    out = capsys.readouterr().out
    assert "PASS" in out
    assert "command_log" not in out


def test_hex_key_file_is_accepted(good_locker, locker_material, tmp_path):
    keyfile = tmp_path / "org.hex"
    keyfile.write_text(locker_material["public_raw"].hex())

    assert cli.run([str(good_locker), "--key", str(keyfile)]) == 0
