from __future__ import annotations

import hashlib
import json

from core.hash_chain import EntryInput, compute_chain
from core.manifest import build_manifest, scope_digest


def _entries():
    return [
        EntryInput(seq=0, kind="command_log", phase="intelligence", size=10,
                   sha256="a"*64, control_ids=[], finding_ids=[], filename=None,
                   created_at="2026-08-26T00:00:00+00:00"),
        EntryInput(seq=1, kind="req_resp", phase="exploitation", size=20,
                   sha256="b"*64, control_ids=["CC6.1"], finding_ids=["f1"],
                   filename="r.json", created_at="2026-08-26T00:01:00+00:00"),
    ]


def _build():
    return build_manifest(
        run_id="run-1", engagement_id="run-1", framework="soc2",
        scope_in=["10.0.0.0/24"], scope_out=[], rules={"max_duration_minutes": 60},
        started_at="2026-08-26T00:00:00+00:00", ended_at="2026-08-26T00:05:00+00:00",
        entries=_entries())


def test_manifest_sha_matches_bytes():
    manifest_bytes, sha = _build()
    assert sha == hashlib.sha256(manifest_bytes).hexdigest()


def test_manifest_is_canonical_and_complete():
    manifest_bytes, _ = _build()
    doc = json.loads(manifest_bytes)
    assert doc["version"] == "pentr-locker-1"
    assert doc["algorithm"] == "sha256-linear-v1"
    assert doc["entry_count"] == 2
    assert doc["run"]["framework"] == "soc2"
    assert doc["run"]["scope_digest"] == scope_digest(["10.0.0.0/24"], [], {"max_duration_minutes": 60})
    _, expected_head = compute_chain("run-1", _entries())
    assert doc["chain_head"] == expected_head
    assert [e["seq"] for e in doc["entries"]] == [0, 1]
    assert doc["entries"][1]["entry_hash"]  # per-entry hash present
    # canonical: re-serializing sorted must equal the stored bytes
    assert json.dumps(doc, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8") == manifest_bytes


def test_scope_digest_is_order_independent_for_rules_keys():
    a = scope_digest(["x"], ["y"], {"a": 1, "b": 2})
    b = scope_digest(["x"], ["y"], {"b": 2, "a": 1})
    assert a == b
