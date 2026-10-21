# pentr-verify

Offline verifier for [Pentr](https://github.com/PentrAI) evidence lockers.

When Pentr finishes a penetration test, it seals all the evidence it captured
(command logs, HTTP requests and responses, screenshots) into a hash chain and
signs the result with the organization's Ed25519 key. The exported locker is a
directory or `.zip` that anyone can check with this tool. You don't need
network access, a database or a Pentr account.

The platform seals lockers with this same code, so a PASS here uses exactly the
checks the platform's own seal is built on.

## Install

```bash
pipx install git+https://github.com/PentrAI/pentr-verify
# or
uv tool install git+https://github.com/PentrAI/pentr-verify
```

The only runtime dependency is `cryptography`. Python 3.12 or newer is required.

## Usage

```bash
pentr-verify locker.zip                     # verify against the key inside the locker
pentr-verify locker.zip --key org-key.pem   # pin the signer's public key
pentr-verify locker/ --json                 # machine-readable report
pentr-verify locker.zip --quiet             # skip the per-artifact listing
```

`--key` accepts a PEM public key, 64 hex characters, or 32 raw bytes.

| Exit code | Meaning |
|-----------|---------|
| `0` | PASS: the locker verified |
| `1` | FAIL: the locker did not verify (tampered, incomplete, or signed by a different key) |
| `2` | Usage error: the input is not a readable locker, or `--key` is unreadable |

### Pinned and unpinned verification

Without `--key`, the locker is checked against the public key it carries. That
proves the locker is internally consistent and has not been modified since it
was signed. It does **not** prove who signed it. To prove provenance, get the
organization's public key through a channel you trust and pass it with `--key`.

## Locker layout

```
manifest.json          # canonical run manifest: every entry, its hash and chain hash
signature_block.json   # the signed bytes: chain head, manifest hash, key id, signed_at
signature.bin          # detached Ed25519 signature over signature_block.json
public_key.pem         # the signer's public key
seal.json              # run id, counts and claims, cross-checked against the above
README.txt             # human instructions
artifacts/<sha256>     # one file per manifest entry, named by its SHA-256
```

## What is checked

1. `seal.json` names a known locker format and algorithms.
2. The signature block binds the exact bytes of `manifest.json`.
3. The key id is the SHA-256 of the public key, and matches the pinned key when `--key` is given.
4. The Ed25519 signature over the signature block verifies.
5. The chain's genesis matches the run id.
6. Every entry hash and the chain head recompute from the entry metadata.
7. Every artifact exists, has the listed size, and hashes to its name.
8. No artifact is present that the manifest does not list.
9. Every claim in `seal.json` matches the signed manifest.

Every failure is reported with a stable code (`signature_invalid`,
`chain_head_mismatch`, `blob_hash_mismatch`, `unlisted_blob`, ...). The full set
is `FAILURE_CODES` in `pentr_verify/locker.py`.

## Limits

- **Key custody is software custody.** The Pentr platform holds each
  organization's private key, encrypted at rest. A valid signature proves the
  platform signed the locker, not that a hardware module did.
- **There is no trusted timestamp.** `signed_at` is the platform's own clock.
- **There is no revocation check.** A locker signed with a key that was later
  retired still verifies.

## Development

```bash
uv run pytest
uv run ruff check .
```

## License

MIT. See [LICENSE](LICENSE).
