<!-- SPDX-License-Identifier: Apache-2.0 -->
# scitt-cose cross-implementation test vectors (v1)

A stable, reproducible vector set for SCITT Signed Statements and COSE
Receipts (RFC 9162 SHA-256 verifiable data structure), contributed for
cross-implementation conformance: run the same committed bytes through *your*
verifier and compare against each vector's `expected.json`.

**A mismatch against your implementation is exactly the report the authors
want** — agreement on *rejection* is as load-bearing as agreement on
acceptance.

## Provenance (these bytes are vendored, not fetched)

The `v1/` bytes and [`SHA256SUMS`](SHA256SUMS) in this directory are vendored
**byte-identical** from a pinned, append-only source:

| | |
|---|---|
| Canonical source | <https://github.com/action-state-group/scitt-cose> |
| Release tag | **v0.1.1** |
| Commit | **`41811d1e3d9b32d000b1e7f26cafdb116f572167`** |
| Upstream path | `test-vectors/` |

These vectors are authoritative *in place* here — a verifier in any future year
can review and reproduce them without fetching anything from the source repo.
The pinned source is named only as **provenance**, so the vendored copy can be
diffed against its origin and any drift detected; it is **not** a location the
WG repo needs to fetch from. To confirm the bytes are unmodified (the
[`.gitattributes`](.gitattributes) in this directory pins every vector file as
non-normalized, so this reproduces byte-for-byte on every platform — including a
`core.autocrlf=true` checkout):

```bash
cd test-vectors/scitt-cose
shasum -a 256 -c SHA256SUMS        # 40/40 OK
```

`manifest.json` here is a **superset** of the upstream manifest: each vector's
`expected` block inlines the decoded protected-header expectations and the
expected negative-result code, so a reviewer sees them from the manifest
without opening each `expected.json`. The canonical per-vector source of truth
remains each vector's `expected.json` (itself vendored and checksum-pinned).

## One-command verify (from the repo root)

The reference runner ships in **scitt-cose ≥ 0.1.0** and reads this directory's
manifest directly:

```bash
pip install "scitt-cose>=0.1.0"
python -m scitt_cose.vectors test-vectors/scitt-cose      # add --json for machines
```

A clean-room Go implementation runs the same manifest in the source repo's CI
on every commit. Both runners exit non-zero on any mismatch — including a
negative vector that unexpectedly verifies. No network access is needed
anywhere in the vector path.

## Layout

```
manifest.json          machine-readable index (provenance, decoded-header + negative-code expectations inline)
SHA256SUMS             digest of every published byte file (immutability, CI-enforced at source)
v1/<vector-id>/
  statement.cose       COSE_Sign1 Signed Statement bytes
  payload.bin          the statement's payload bytes (opaque)
  receipt.cose         COSE Receipt bytes
  issuer-key.pub       PEM public key for the statement signature
  log-key.pub          PEM public key of the (simulated) transparency log
  *.test-private       the TEST-ONLY private keys used to mint the vector
  expected.json        every value a verifier needs + the expected verdict
```

### The vectors

| id | result | failure_code |
|---|---|---|
| `valid-eddsa` | VALID | — |
| `valid-es256` | VALID | — |
| `fail-tampered-path` | INVALID | `TAMPERED_INCLUSION_PATH` |
| `fail-unsupported-vds` | INVALID | `UNSUPPORTED_VDS` |
| `fail-bad-statement-sig` | INVALID | `BAD_STATEMENT_SIGNATURE` |

Each negative vector isolates exactly one failure: `fail-tampered-path` and
`fail-unsupported-vds` carry an honest statement (only the receipt must be
rejected); `fail-bad-statement-sig` carries a verifying receipt minted over the
digest of the tampered statement bytes (only the statement signature must be
rejected).

## `expected.json` / manifest `expected` fields

| field | meaning |
|---|---|
| `payload_sha256` | SHA-256 (hex) of `payload.bin` |
| `protected_header.statement` | decoded statement protected header: `alg` (name) + `alg_code` (COSE code point), `content_type` (label 3), CWT Claims at label 15 → `issuer` (claim 1) and `subject` (claim 2) |
| `protected_header.receipt` | decoded receipt protected header: `alg`/`alg_code`, `vds` at label 395 (`1` = RFC9162_SHA256) |
| `leaf_entry` | hex of the log's leaf entry for this statement (see below) |
| `leaf_index`, `tree_size` | position of the leaf and size of the log |
| `inclusion_path` | the RFC 9162 audit path, outermost-last, hex per node (for `fail-tampered-path` this is the path *as committed*, i.e. with the flipped byte) |
| `reconstructed_root` | the Merkle root (hex) a correct verifier reconstructs; `null` when the receipt must be rejected before/without root agreement |
| `statement_signature_valid` | must the statement signature verify? |
| `receipt_valid` | must the receipt verify? |
| `result` | `VALID` \| `INVALID` (overall) |
| `failure_code` | present on INVALID vectors only |

> Note on `reconstructed_root: null` (`fail-unsupported-vds`): this reflects one
> conformant ordering — reject on the unsupported `vds` (read from the
> *protected* header) before reconstructing a root. A verifier that
> reconstructs the root first and then rejects is equally conformant; the
> `null` is informative, not a required check order.

## Deterministic tree construction (rebuild the log state yourself)

* **Leaf entry definition:** the transparency log's leaf entry for a registered
  Signed Statement is the **SHA-256 digest of the complete COSE_Sign1 statement
  bytes** (for `fail-bad-statement-sig`, the digest of the tampered bytes as
  committed — the log registered what it was given). Both runners recompute the
  digest from `statement.cose` and assert it equals the `leaf_entry`, so an
  implementation that derives the leaf differently fails the suite.
* **Tree:** RFC 9162 SHA-256 Merkle tree, `tree_size = 8`, leaves in index
  order. The statement's digest sits at `leaf_index = 2`; every other leaf `i`
  is `SHA-256("scitt-cose test vectors v1 :: <vector-id> :: filler leaf <i>")`
  (ASCII).
* The receipt's payload is the Merkle root (detached); its unprotected header
  carries the inclusion proof as `cbor([tree_size, leaf_index, [audit_path]])`
  at vdp (label 396) key `-1`, per draft-ietf-cose-merkle-tree-proofs.

## Keys

All keys were freshly generated for this vector set, are committed here in
full (including private halves, named `*.test-private`), are **TEST-ONLY**, and
are never used anywhere else. Do not use them for anything.
