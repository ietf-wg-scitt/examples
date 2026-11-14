# Audit coverage: reproducible local fixture

This small executable fixture signs and verifies real Ed25519 COSE_Sign1
structures. Audit statement **A** directly declares the exact set **{S1, S2}**.
Correction **S3** has the same issuer and subject as S2 and a later synthetic
`iat`; it is still outside A's declared set. The example is local, uses fixed
public test keys, and makes no deployed-implementation or conformance claim.

## Run

Requires Python 3 and `cryptography` (tested with version 50.0.1). The CBOR codec
is included and restricted to the definite-length fixture subset; no `cbor2`
dependency, network access, service, or account is needed.

```sh
python3 run_demo.py --out result.json
```

The checked run in `result.json` contains **29 passing checks**. A failed check
raises an exception and prevents generation of a success result. Private key
seeds `0x11 * 32` and `0x22 * 32` are intentionally public, **test-only** inputs.
Do not use them outside this fixture.

## Existing primitives and local choices

Each statement uses tagged COSE_Sign1 with an embedded JSON payload, an empty
external AAD, and protected `alg` (-19, Ed25519), `content type`, `kid`, and CWT
Claims (`iss`, `sub`, `iat`). Verification pins public keys by `(iss, kid)`;
it does not validate issuer authority. The audit relation, identity-profile
name, target list, and `exact`/`partial` mode are inside the **signed payload**.
All vocabulary prefixed with `demo` is local and unregistered.

A signed payload that repeats a member name in any JSON object is refused,
because a first-wins and a last-wins parser read different documents from the
same bytes. A target list is read only when it is a list whose every entry has
this profile's identifier syntax: `sha256:` followed by 64 lowercase hexadecimal
digits. No entry is normalized.

The identity profile is also explicitly local:

```text
ID = "sha256:" || hex(SHA-256(encode(tag 18, [P, {}, L, signature])))
```

`P` is the original protected-header byte string and `L` the original embedded
payload byte string. Their contents and the signature bytes are preserved
exactly. Only the outer tag, four-item array, empty unprotected map, and byte
string lengths are encoded using the fixture's shortest definite-length
encoding. The resulting projection equals the original receipt-free statement
bytes generated here.

This is **not a universal COSE identifier or canonicalization claim**. Untagged,
detached-payload, indefinite-length, and nonshortest outer encodings are outside
this profile. Re-encoding protected-header contents changes the signed bytes;
the projection does not normalize them. Alternative valid serializations and
signature algorithms require an explicitly defined profile before comparison.

## What the checks demonstrate

| Scenario | Observed result |
| --- | --- |
| Replace S2 with the latest record sharing `iss`/`sub` | The deliberately naive resolver chooses S3. |
| Check S3 against A's exact target IDs | S3 is outside A's declared coverage. |
| Check an unlisted S3 against a partial list | Coverage remains unresolved. |
| Omit the coverage mode, or use an unknown mode | Scope remains unresolved. |
| Fail to retrieve declared target S2 | S2 is declared but unavailable; it is not classified as excluded. |
| Alter a signed target digest, list, or mode | A's signature verification fails. |
| Alter S2's payload | Its ID changes and its signature fails. |
| Inject a broader list into unsigned metadata | The signature still verifies; the evaluator reads the signed payload and excludes S3. |
| Append different unsigned carrier metadata | Raw carrier hashes differ; projected statement identity and signature verification stay the same. |
| B directly covers A; A directly covers S1 | B's declaration does not acquire S1 through transitivity. |
| Damage one entry of an exact target list | The list is not readable; no membership and no exclusion is inferred for any target. |
| Write S2's entry in upper-case hex digits or under another prefix, or put a number in the list | The same result: the entry is outside this profile's identifier syntax. |
| Give the targets as one string, or as an object with an identifier as a member name | Scope remains unresolved; the string is not searched and the member names are not read as a list. |
| Repeat a member name in a signed payload | The signature verifies and the payload is refused. |

The carrier experiment uses arbitrary unsigned metadata named as placeholders.
**It generates and verifies no Transparency Service receipts and performs no
registrations.** It demonstrates the byte-projection issue that a registration
carrier can create; it does not establish receipt validity, inclusion,
consistency, or registration-time properties.

## Claim boundary

The verified signature authenticates the local declaration under a pinned key,
and the target digests bind the chosen record bytes under this identity profile.
An exact list is an exhaustive declaration of **A's own coverage**. It does not
prove global completeness, completeness of an audit task, truth or adequacy of
an audit, execution, delivery, retention, or absence of an unavailable record.
The synthetic `iat` values are signed issuer assertions, not trusted timestamps.
Correction links do not transfer coverage automatically.

This fixture establishes a working payload-aware application baseline using
existing signing and hashing primitives. It does not establish that SCITT needs
a common protected-header convention. Nor does it disprove an issuer-specific
identity scheme using `iss`, `sub`, `iat`, or epoch markers with explicit rules.
A payload-independent consumer requirement and its missing interoperability
contract must be justified separately.

Relevant standards background: [RFC 9943](https://www.rfc-editor.org/rfc/rfc9943),
[RFC 9052](https://www.rfc-editor.org/rfc/rfc9052), and
[RFC 9864](https://www.rfc-editor.org/rfc/rfc9864).

## Revision of 14 November 2026

The last four rows of the table above were added, with five checks. Before
this revision the fixture answered that a statement was outside the declared
coverage when its list entry was damaged or written in upper-case hex digits,
searched a string of targets as text, read the member names of an object as a
list, and read the last of two members with one name.

The damaged-entry case follows case C13 of
[draft-gruszka-scitt-statement-identification-03](https://datatracker.ietf.org/doc/html/draft-gruszka-scitt-statement-identification-03),
where a reference that is not well-formed is not usable and the match is
INDETERMINATE. The refusal of a repeated member name follows finding F6 of the
[Joint Interoperability Report](https://doi.org/10.5281/zenodo.23333369),
found by Konrad Gruszka. The statement identifiers and the first 24 checks are
unchanged.
