"""Offline reader and verifier for an exported evidence locker.

PURE MODULE — imports nothing from server/, scheduler/, or SQLAlchemy. It must
run on an auditor's machine that has never seen the Pentr database. Every hash
here is recomputed with the exact same primitives that produced the seal
(core.hash_chain, core.manifest, core.signing), which is what makes a PASS
mean something: the verifier cannot drift from the sealer.
"""
from __future__ import annotations

import re
import zipfile
from pathlib import Path

# The locker *packaging* format version, independent of core.manifest.VERSION
# and core.signing.SIGNATURE_VERSION even though all three read "pentr-locker-1"
# today. These are three separately-versioned concerns that happened to ship
# together in Phase 4: the manifest schema, the signature block schema, and the
# container format. Aliasing to either would mean bumping the schema version
# silently changes what the locker advertises, making them unable to move
# independently.
LOCKER_FORMAT = "pentr-locker-1"

MANIFEST_NAME = "manifest.json"
SIGNATURE_BLOCK_NAME = "signature_block.json"
SIGNATURE_NAME = "signature.bin"
PUBLIC_KEY_NAME = "public_key.pem"
SEAL_NAME = "seal.json"
README_NAME = "README.txt"

ROOT_FILES = frozenset({
    MANIFEST_NAME, SIGNATURE_BLOCK_NAME, SIGNATURE_NAME,
    PUBLIC_KEY_NAME, SEAL_NAME, README_NAME,
})
_ARTIFACT_MEMBER = re.compile(r"^artifacts/[0-9a-f]{64}$")


def _validate_member_name(name: str) -> None:
    """Validate that a member name is in the locker allowlist.

    Raises LockerFormatError if the name is not one of the root files or a
    valid artifact path. This guards against path traversal attacks and
    unexpected members.
    """
    if name in ROOT_FILES or _ARTIFACT_MEMBER.match(name):
        return
    raise LockerFormatError(f"not a valid locker member: {name!r}")


class LockerFormatError(Exception):
    """The locker is unreadable or structurally malformed.

    Distinct from a verification failure: this is "you gave me something that
    is not a locker", which the CLI reports as exit 2, not as tampering.
    """


class Locker:
    """Read-only view over a locker directory or zip."""

    def __init__(self, source: str) -> None:
        self.source = source

    def read(self, name: str) -> bytes:
        """Read a locker member by name.

        Validates that the name is in the allowlist (root files or artifacts)
        before delegating to the backend, guarding against path traversal
        attacks in both directory and zip lockers.
        """
        _validate_member_name(name)
        return self._read_member(name)

    def _read_member(self, name: str) -> bytes:
        """Read a locker member (implemented by subclasses)."""
        raise NotImplementedError

    def list_artifact_names(self) -> set[str]:
        raise NotImplementedError

    def read_artifact(self, sha256: str) -> bytes:
        return self.read(f"artifacts/{sha256}")


class _DirLocker(Locker):
    def __init__(self, root: Path) -> None:
        super().__init__(str(root))
        self._root = root

    def _read_member(self, name: str) -> bytes:
        path = self._root / name
        if not path.is_file():
            raise LockerFormatError(f"locker is missing {name}")
        return path.read_bytes()

    def list_artifact_names(self) -> set[str]:
        # Deliberately does not filter by hex name. Stage 9 of verify_locker
        # must be able to see a smuggled file (e.g., artifacts/secret.txt) in
        # order to fail on it as unlisted_blob. If we filtered here, a smuggled
        # file would be invisible and the locker would pass, silently breaking
        # the strict both-way check.
        adir = self._root / "artifacts"
        if not adir.is_dir():
            return set()
        return {p.name for p in adir.iterdir() if p.is_file()}


class _ZipLocker(Locker):
    def __init__(self, path: Path) -> None:
        super().__init__(str(path))
        try:
            self._zf = zipfile.ZipFile(path)
        except (zipfile.BadZipFile, OSError) as exc:
            raise LockerFormatError(f"not a readable zip: {path}") from exc
        self._names = {i.filename for i in self._zf.infolist() if not i.is_dir()}
        # Validate every member up front. Nothing is extracted to disk, but an
        # unexpected name means this is not a locker we understand — and an
        # absolute or traversing path is a hostile archive, not a typo.
        for name in self._names:
            if name in ROOT_FILES or _ARTIFACT_MEMBER.match(name):
                continue
            raise LockerFormatError(f"unexpected member in locker zip: {name!r}")

    def _read_member(self, name: str) -> bytes:
        if name not in self._names:
            raise LockerFormatError(f"locker is missing {name}")
        return self._zf.read(name)

    def list_artifact_names(self) -> set[str]:
        return {n.split("/", 1)[1] for n in self._names if n.startswith("artifacts/")}


def open_locker(path: str | Path) -> Locker:
    p = Path(path)
    if p.is_dir():
        return _DirLocker(p)
    if p.is_file():
        return _ZipLocker(p)
    raise LockerFormatError(f"no such locker: {p}")
