# Offline inclusion-path check with the standard library only

Author: Xinghua Zhao

Status: Local demonstrator. No Transparency Service, no keys, no signatures, no receipts, no network access, and no interoperability results. Revised 19 November 2026.

## Consumer and failure mode

An auditor holds a 32-byte root, one RFC 9162 inclusion path, and a leaf input. It has no ledger access and does not want to install a COSE library to answer one question: **does this leaf belong to that tree?**

The failure this case isolates is a reading error, not a cryptographic one. RFC 9162 defines the leaf hash as `SHA-256(0x00 || leaf_input)` and the node hash as `SHA-256(0x01 || left || right)`. A reader that treats the *leaf-input digest* — `SHA-256(leaf_input)` — as the leaf hash, or drops the domain-separation prefixes, runs the same fold over the same path and gets a different root.

That error is over-strict rather than permissive: an honest tree gets reported as broken. In this demo it costs two false alarms out of two honest vectors. The same shape of error produced five false alarms out of five when a COSE vector set was first read by a checker in the contributing project; the reading was corrected, not the vectors.

## Minimum relation

For the check to mean anything, three things must be fixed and bound before the fold runs:

- the leaf-input encoding, so `leaf_input` bytes can be reproduced from the record;
- the domain-separation rule, so leaf and node hashes cannot be confused;
- the tree size and leaf index, so the path is folded in the one order that is defined.

No completeness, ordering, or freshness claim is implied. A passing fold says the leaf is in that tree. It says nothing about whether the statement behind the leaf is true, recent, or complete.

## What the demo shows

Two readers over the same five vectors, both standard-library only:

| reader | leaf hash used | agrees with expected verdict |
|---|---|---|
| `strict` | `SHA-256(0x00 \|\| leaf_input)` | 5 / 5 |
| `naive` | `SHA-256(leaf_input)` | 3 / 5 — rejects both honest proofs |

The three negative vectors (`fail-tampered-path`, `fail-wrong-leaf-index`, `fail-wrong-tree-size`) are rejected by both readers, which is why the naive reader still scores 3 / 5. The disagreement is entirely on the positive vectors.

Full per-vector output is in `demo/result.json`, produced by running the demo; nothing in it is typed by hand.

## What this case does not cover

- No COSE_Sign1 statement, receipt, or key material.
- No check on whether the root itself is trustworthy, or which tree it belongs to.
- No tree-construction from scratch, and no consistency or inclusion-across-trees proof.
- No behaviour for `tree_size` or `leaf_index` outside the vector ranges.

## Files

```
use-cases/inclusion-proof-offline/README.md        this file
use-cases/inclusion-proof-offline/SHA256SUMS       digests of the vectors and the demo output
use-cases/inclusion-proof-offline/vectors/*.json   five vectors, one per verdict
use-cases/inclusion-proof-offline/demo/run_demo.py  strict and naive readers
use-cases/inclusion-proof-offline/demo/result.json  output of the run above
```

The vectors are the same shape as `test-vectors/scitt-rfc9162` in the contributing project, so this case can be read as a demonstration of how that shape is consumed. They are copied here rather than referenced, so the demo runs from a checkout with no dependency on another submission.

## Run

From the repository root:

```
python3 use-cases/inclusion-proof-offline/demo/run_demo.py \
  --out use-cases/inclusion-proof-offline/demo/result.json
```

Exit status is 0 only when the strict reader agrees with every expected verdict. Python 3.8 or later; no third-party packages.
