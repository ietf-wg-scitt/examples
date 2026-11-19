# Examples

This project contains a number of examples and test cases for the IETF SCITT WG specification.

# cose-hash-envelope-0

This is a Signed Statement using [COSE Hash Envelope](https://datatracker.ietf.org/doc/draft-ietf-cose-hash-envelope/), produced by a Microsoft issuer, and made transparent in test DataTrails and Microsoft ledgers.

The Signed Statement commits to the digest of an [in-toto](https://github.com/in-toto/attestation) Statement (`application/vnd.in-toto+json`) describing the [Phi-4-reasoning](https://huggingface.co/microsoft/Phi-4-reasoning) model. The CWT subject is `experimental/microsoft/phi-4-reasoning`, and the issuer is identified by a `did:x509` with the Microsoft Signing Transparency EKU `1.3.6.1.4.1.311.76.59.1.1`. The in-toto manifest and recreation steps are documented at <https://github.com/achamayou/scitt-for-phi>.

Two Transparent Statements, embedding respectively one and two receipts are available.

Files:

```
signed-statements/cose-hash-envelope-0.scitt
receipts/cose-hash-envelope-0-datatrail-mmr.receipt
transparent-statements/cose-hash-envelope-0-with-microsoft-mst-receipt.scitt
transparent-statements/cose-hash-envelope-0-with-microsoft-mst-and-datatrails-mmr-receipts.scitt
```

# scitt-cose cross-implementation test vectors (v1)

A self-contained, append-only set of SCITT Signed Statement + COSE Receipt
(RFC 9162 SHA-256) conformance vectors — two positive (EdDSA, ES256) and three
negative, each isolating one failure (`TAMPERED_INCLUSION_PATH`,
`UNSUPPORTED_VDS`, `BAD_STATEMENT_SIGNATURE`). Every vector ships the
statement/receipt bytes, keys, the decoded protected-header expectations, the
expected root/path material, and the explicit negative outcome.

The bytes are vendored byte-identical from the pinned, append-only source
`action-state-group/scitt-cose` tag **v0.1.1**
(`41811d1e3d9b32d000b1e7f26cafdb116f572167`) and carry a `SHA256SUMS` so the
copy can be verified in place and diffed against its origin. A reference runner
ships in `scitt-cose >= 0.1.0`; a clean-room Go runner exercises the same
manifest in the source repo's CI.

```
test-vectors/scitt-cose/README.md       provenance, verify steps, field reference
test-vectors/scitt-cose/manifest.json   index with decoded headers + negative codes inline
test-vectors/scitt-cose/SHA256SUMS       digest of every byte file
test-vectors/scitt-cose/v1/<id>/...      statement.cose, receipt.cose, payload.bin, keys, expected.json
```

Verify (all commands from the repo root):

```
# Integrity — SHA256SUMS paths are relative to the suite dir, so check inside it
# (the subshell keeps the cd from leaking into the next command):
( cd test-vectors/scitt-cose && shasum -a 256 -c SHA256SUMS )

# Conformance runner:
pip install "scitt-cose>=0.1.0"
python -m scitt_cose.vectors test-vectors/scitt-cose
```

# scitt-rfc9162 hash-tree and inclusion-path test vectors (v1)

A self-contained, append-only set of **RFC 9162 SHA-256 hash-tree and
inclusion-path** vectors: two positive and three negative, each negative
isolating one failure (`INVALID_INCLUSION_PATH`, `INVALID_TREE_SIZE`,
`INVALID_LEAF_INDEX`).

This set covers the tree layer only, and deliberately ships **no COSE bytes**, so
a reader can check the fold arithmetic with the standard library and no COSE
library. It is complementary to `test-vectors/scitt-cose` above, which covers the
COSE envelope and receipt layer; neither substitutes for the other.

Files:

```
test-vectors/scitt-rfc9162/README.md        what each field means, and the fold rule
test-vectors/scitt-rfc9162/manifest.json    index with every expected block inlined
test-vectors/scitt-rfc9162/SHA256SUMS       every vector file, byte-for-byte
test-vectors/scitt-rfc9162/v1/<vector-id>/expected.json
```

Verification needs no code from the contributing project: for each vector,
`SHA-256(leaf_input)` must equal `digest_hex`; folding `inclusion_path` over
`leaf_index` with `tree_size` per RFC 9162 must equal `root_true` for the `VALID`
vectors, and must differ for the three `fail-*` vectors. A verifier that
*accepts* any `fail-*` vector is a finding about one of us — please open an issue
rather than staying silent.
