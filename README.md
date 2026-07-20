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

# aac-interop-es256 — two-TS Transparent Statement (CCF + RFC 9162 SHA-256)

A Signed Statement (`ES256`, `did:x509`, `application/json`) issued by Amaury Chamayou
(Microsoft) and made transparent in two independent Transparency Services:

- **Microsoft CCF** (dev node, `ccf.v1` profile, `vds=2`, txid `2.15`) — ES384 receipt
- **Action State Group** (live service, RFC 9162 SHA-256, `vds=1`) — EdDSA receipt

This demonstrates that receipt profiles can be used in conjunction as well as in isolation
(following the pattern introduced by `cose-hash-envelope-0-with-microsoft-mst-and-datatrails-mmr-receipts.scitt`).

**Note:** the Microsoft receipt is from a CCF dev node, not a production deployment.

The statement payload is an `application/json` Agent Action Capsule interop artifact
([draft-mih-scitt-agent-action-capsule](https://datatracker.ietf.org/doc/draft-mih-scitt-agent-action-capsule/)),
produced as part of IETF 126 / Vienna 2026 cross-implementation interop work.

Files:

```
transparent-statements/aac-interop-es256-with-microsoft-ccf-dev-and-asg-rfc9162-receipts.scitt
```

Verify:

```python
import cbor2, hashlib
from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from scitt_cose import verify_receipt  # pip install scitt-cose>=0.1.0

ts = open("transparent-statements/aac-interop-es256-with-microsoft-ccf-dev-and-asg-rfc9162-receipts.scitt","rb").read()
decoded = cbor2.loads(ts)
ph_bytes, uh, payload, sig = decoded.value

# The statement bytes are Amaury's signed statement (same bytes, reassembled):
# statement SHA-256 (leaf entry): 02ec7822cd91641c74ee0d125ad9b89fc6961400c6efb69ec9aff65f3b23d567
leaf_hex = "02ec7822cd91641c74ee0d125ad9b89fc6961400c6efb69ec9aff65f3b23d567"

receipts = uh[394]
assert len(receipts) == 2, f"expected 2 receipts, got {len(receipts)}"

# receipt[0] — Microsoft CCF (vds=2, ES384)
# Obtain the CCF service public key from the x5t header in the receipt's protected header,
# or from the service identity certificate at:
#   achamayou/scitt-ccf-ledger:produce-ccf-profile-receipts-for-capsule
#   test/test_vectors/ccf-profile-capsule/service-identity.pem
# ccf_pub_pem = <P-384 public key extracted from service-identity.pem>
# result0 = verify_receipt(receipts[0], leaf_entry_hex=leaf_hex, log_public_key_pem=ccf_pub_pem)

# receipt[1] — Action State Group RFC 9162 SHA-256 (vds=1, EdDSA)
asg_ts_pub_pem = """-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAObtlTJ3Ar+HA7e8N7/qmkJm4UYg2ybom4EkVNYQPlrU=
-----END PUBLIC KEY-----"""
result1 = verify_receipt(receipts[1], leaf_entry_hex=leaf_hex, log_public_key_pem=asg_ts_pub_pem)
assert result1.ok, result1.errors
print("ASG RFC9162 receipt: ok=True  root=" + result1.root)
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