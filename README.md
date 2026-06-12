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