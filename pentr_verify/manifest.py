from __future__ import annotations

import hashlib
import json

from core.hash_chain import EntryInput, compute_chain, genesis

VERSION = "pentr-locker-1"
ALGORITHM = "sha256-linear-v1"


def _canon_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def scope_digest(scope_in: list[str], scope_out: list[str], rules: dict) -> str:
    payload = _canon_bytes({"scope_in": scope_in, "scope_out": scope_out, "rules": rules})
    return hashlib.sha256(payload).hexdigest()


def build_manifest(*, run_id: str, engagement_id: str, framework: str,
                   scope_in: list[str], scope_out: list[str], rules: dict,
                   started_at: str | None, ended_at: str | None,
                   entries: list[EntryInput]) -> tuple[bytes, str]:
    entry_hashes, chain_head = compute_chain(run_id, entries)
    manifest = {
        "version": VERSION,
        "algorithm": ALGORITHM,
        "genesis": genesis(run_id),
        "run": {
            "engagement_id": engagement_id,
            "framework": framework,
            "scope_digest": scope_digest(scope_in, scope_out, rules),
            "started_at": started_at,
            "ended_at": ended_at,
        },
        "entries": [
            {
                "seq": e.seq,
                "sha256": e.sha256,
                "kind": e.kind,
                "phase": e.phase,
                "control_ids": sorted(e.control_ids),
                "finding_ids": sorted(e.finding_ids),
                "size": e.size,
                "filename": e.filename,
                "created_at": e.created_at,
                "entry_hash": h,
            }
            for e, h in zip(entries, entry_hashes)
        ],
        "chain_head": chain_head,
        "entry_count": len(entries),
    }
    manifest_bytes = _canon_bytes(manifest)
    return manifest_bytes, hashlib.sha256(manifest_bytes).hexdigest()
