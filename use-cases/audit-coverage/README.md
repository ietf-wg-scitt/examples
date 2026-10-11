# Exact declared audit coverage across corrections and registrations

Author: Mikhail Sergeev

Status: Local COSE demonstrator; no deployment or Transparency Service interoperability results. Revised 11 October 2026.

## Consumer and failure mode

An application auditor signs A, declaring coverage of exactly {S1, S2}: a build record and a scan result. The producer later issues correction S3 with the same `iss` and `sub` as S2.

A consumer that substitutes the newest same-subject record can incorrectly present A as covering S3 while A's signature remains valid. It needs to check membership in A's declared set before applying A's conclusions.

## Minimum relation

The required meaning is: **A's issuer declares these exact Signed Statements as the complete scope of this particular assessment.**

The direct relations are A-to-S1 and A-to-S2, with the set declared exhaustive for A's assessment. The relation, assessment context, target identities and exhaustive-versus-partial interpretation must be cryptographically bound to A. An authenticated profile may define that interpretation; a new completeness field is not inherently necessary. A correction relation from S3 to S2 is unnecessary for this membership question. Coverage does not propagate transitively.

Each target needs an explicit identity profile, including the hash preimage and encoding rules when digests are used. Statement identity is distinct from a registration or receipt locator, so another registration does not change membership.

| Input | Required result |
| --- | --- |
| A declares exactly {S1, S2}; supplied target is S2 | In A's declared scope |
| Same A; supplied target is distinct S3 | Outside A's declared scope |
| A lists S1 and S2 only partially; S3 is absent | Coverage of S3 undetermined |
| Exhaustive interpretation is absent or unsupported | No exclusion inferred |
| S2 is listed but its bytes cannot be obtained | Declared reference known; target verification unresolved |
| A's signed list, target digest or scope mode is altered | Signature verification fails; no authenticated scope result |
| A broader list is injected into unsigned metadata | Ignore it; A's authenticated scope still excludes S3 |
| Only unsigned carrier metadata changes | Original target identity and declared membership unchanged under the selected profile |

## Local implementation and interoperability question

The [fixture](demo/README.md) uses [COSE_Sign1](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4)/Ed25519, with the coverage declaration in A's signed payload. The deliberately incorrect consumer chooses S3 while A's signature remains valid; the exact-reference consumer excludes S3. Re-execution on 11 October reproduced all 24 checks and the saved [result](demo/result.json) byte for byte. This is another execution of the same source, not an independently authored implementation.

Its local SHA-256 identity profile preserves protected-header, inline payload and signature bytes while projecting the unprotected map to empty. The encoding restrictions are documented; this is not a universal COSE identifier. Unsigned carrier additions are synthetic: no TS registration or receipt verification is exercised.

An application-specific signed manifest therefore provides a working baseline. Do implementors need shared interpretation of this declaration without understanding each audit payload format? Payload-independent interpretation does not remove the need for bytes required by signature verification or reference resolution.

[CPB-05][cpb] and [POB-00][pob] offer proposed reference mechanisms to evaluate. This case selects no wire format, requests no new header allocation, and establishes no necessity for a new carrier or cryptographic primitive.

## Authentication, completeness and authority

These are separate results:

| Question | What this case establishes or requires |
| --- | --- |
| Did the signing key authenticate this declaration? | Signature verification authenticates the signed bytes under the selected key. The fixture pins keys locally; real issuer identity needs its own binding. |
| What set did the issuer declare? | The authenticated exact list is {S1, S2}. S3 is outside that declaration; absence from a partial list remains undetermined. |
| Was the audit actually complete? | Not established. Audit execution, actual scope, task completeness, conclusions and the correctness of S3 require separate evidence. |
| May the relying party treat this issuer's relation as authoritative? | A separate policy or mandate must establish the issuer's authority for this assessment and relation, including cross-issuer targets. Signing or registration alone does not grant it. |

A valid declaration can remain inspectable even when authority is unknown or denied; the relying party does not promote it to an authorized audit result. The fixture does not implement that authorization decision. [SCITT receipts][receipts] establish their specified VDS properties, not authority to audit or factual audit completeness.

This is observed behavior of a synthetic fixture, not a reported production incident, an independent implementation or a protected-header interoperability result.

The scenario continues the author's [September SCITT contribution][origin]. The protected-header approach remains a question for implementors.

[receipts]: https://www.rfc-editor.org/rfc/rfc9942.html
[cpb]: https://datatracker.ietf.org/doc/html/draft-mih-sokolov-scitt-payload-binding-05#section-8
[pob]: https://datatracker.ietf.org/doc/html/draft-nobuo-scitt-protected-object-binding-00#section-12
[origin]: https://mailarchive.ietf.org/arch/msg/scitt/aCT0rhL_efV_4xGMlZA-h9jR6jE/

