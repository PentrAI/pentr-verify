from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

GENESIS_PREFIX = "pentr-evidence-locker-v1|"


@dataclass(frozen=True)
class EntryInput:
    seq: int
    kind: str
    phase: str
    size: int
    sha256: str
    control_ids: list[str]
    finding_ids: list[str]
    filename: str | None
    created_at: str


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def genesis(run_id: str) -> str:
    return hashlib.sha256((GENESIS_PREFIX + run_id).encode("utf-8")).hexdigest()


def entry_metadata(entry: EntryInput) -> str:
    return _canon({
        "seq": entry.seq,
        "kind": entry.kind,
        "phase": entry.phase,
        "size": entry.size,
        "control_ids": sorted(entry.control_ids),
        "finding_ids": sorted(entry.finding_ids),
        "filename": entry.filename,
        "created_at": entry.created_at,
    })


def entry_hash(prev_hex: str, artifact_sha256: str, metadata_json: str) -> str:
    payload = prev_hex + artifact_sha256 + metadata_json
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def compute_chain(run_id: str, entries: list[EntryInput]) -> tuple[list[str], str]:
    prev = genesis(run_id)
    hashes: list[str] = []
    for entry in entries:
        prev = entry_hash(prev, entry.sha256, entry_metadata(entry))
        hashes.append(prev)
    head = hashes[-1] if hashes else genesis(run_id)
    return hashes, head
