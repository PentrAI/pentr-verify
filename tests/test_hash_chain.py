from __future__ import annotations

from core.hash_chain import EntryInput, compute_chain, genesis


def _entries():
    return [
        EntryInput(seq=0, kind="command_log", phase="intelligence", size=10,
                   sha256="a"*64, control_ids=[], finding_ids=[], filename=None,
                   created_at="2026-08-26T00:00:00+00:00"),
        EntryInput(seq=1, kind="req_resp", phase="exploitation", size=20,
                   sha256="b"*64, control_ids=["CC6.1"], finding_ids=["f1"],
                   filename="r.json", created_at="2026-08-26T00:01:00+00:00"),
    ]


def test_chain_is_deterministic():
    h1, head1 = compute_chain("run-1", _entries())
    h2, head2 = compute_chain("run-1", _entries())
    assert h1 == h2 and head1 == head2
    assert len(h1) == 2
    assert head1 == h1[-1]


def test_genesis_binds_run_id():
    _, head_a = compute_chain("run-A", _entries())
    _, head_b = compute_chain("run-B", _entries())
    assert head_a != head_b  # same artifacts, different run -> different head


def test_one_mutated_byte_changes_head():
    good = _entries()
    _, head_good = compute_chain("run-1", good)
    tampered = _entries()
    tampered[1] = EntryInput(**{**tampered[1].__dict__, "sha256": "c"*64})
    _, head_bad = compute_chain("run-1", tampered)
    assert head_good != head_bad


def test_reordering_changes_head():
    _, head_good = compute_chain("run-1", _entries())
    _, head_swapped = compute_chain("run-1", list(reversed(_entries())))
    assert head_good != head_swapped


def test_empty_chain_head_is_genesis():
    hashes, head = compute_chain("run-1", [])
    assert hashes == []
    assert head == genesis("run-1")
