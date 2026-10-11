#!/usr/bin/env python3
"""Local COSE_Sign1 coverage fixture; no Transparency Service or receipts.

Uses real Ed25519 signatures and a deliberately limited CBOR codec. Fixed private
key seeds are PUBLIC, TEST-ONLY material. Do not use these keys for any other work.
"""

import argparse
import hashlib
import json
from dataclasses import dataclass
from importlib.metadata import version
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


@dataclass(frozen=True)
class Tag:
    number: int
    value: object


def head(major, value):
    """Shortest definite-length encoding, limited to unsigned 64-bit arguments."""
    for limit, extra, width in ((24, 0, 0), (256, 24, 1), (65536, 25, 2),
                                (2**32, 26, 4), (2**64, 27, 8)):
        if value < limit:
            return bytes([(major << 5) | (value if width == 0 else extra)]) + (
                value.to_bytes(width, "big") if width else b"")
    raise ValueError("CBOR integer too large for this fixture")


def encode(value):
    """Fixture subset only: integers, bstr, tstr, arrays, maps, tags."""
    if type(value) is int:
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        data = value.encode("utf-8")
        return head(3, len(data)) + data
    if isinstance(value, (list, tuple)):
        return head(4, len(value)) + b"".join(encode(x) for x in value)
    if isinstance(value, dict):
        # Insertion order is intentional. This is not a general canonicalizer.
        return head(5, len(value)) + b"".join(
            encode(k) + encode(v) for k, v in value.items())
    if isinstance(value, Tag):
        return head(6, value.number) + encode(value.value)
    raise TypeError(f"Unsupported fixture CBOR type: {type(value).__name__}")


def decode(data):
    """Reject indefinite/nonshortest encodings and duplicate map keys."""
    offset = 0

    def take(size):
        nonlocal offset
        if offset + size > len(data):
            raise ValueError("Truncated CBOR")
        result = data[offset:offset + size]
        offset += size
        return result

    def item():
        initial = take(1)[0]
        major, ai = initial >> 5, initial & 31
        if ai < 24:
            n = ai
        elif ai in (24, 25, 26, 27):
            width = 1 << (ai - 24)
            n = int.from_bytes(take(width), "big")
            if n < {1: 24, 2: 256, 4: 65536, 8: 2**32}[width]:
                raise ValueError("Nonshortest encoding outside this local profile")
        else:
            raise ValueError("Indefinite/reserved encoding outside this profile")
        if major == 0:
            return n
        if major == 1:
            return -1 - n
        if major == 2:
            return take(n)
        if major == 3:
            return take(n).decode("utf-8")
        if major == 4:
            return [item() for _ in range(n)]
        if major == 5:
            result = {}
            for _ in range(n):
                key, value = item(), item()
                if key in result:
                    raise ValueError("Duplicate map key")
                result[key] = value
            return result
        if major == 6:
            return Tag(n, item())
        raise ValueError("Unsupported fixture CBOR major type")

    result = item()
    if offset != len(data):
        raise ValueError("Trailing CBOR data")
    return result


# These fixed seeds are PUBLIC TEST-ONLY fixture inputs, not credentials.
PRODUCER = Ed25519PrivateKey.from_private_bytes(bytes([0x11]) * 32)
AUDITOR = Ed25519PrivateKey.from_private_bytes(bytes([0x22]) * 32)
PRODUCER_ISS = "https://producer.example"
AUDITOR_ISS = "https://auditor.example"
KIDS = {PRODUCER_ISS: b"producer-demo", AUDITOR_ISS: b"auditor-demo"}
KEYS = {(PRODUCER_ISS, KIDS[PRODUCER_ISS]): PRODUCER.public_key(),
        (AUDITOR_ISS, KIDS[AUDITOR_ISS]): AUDITOR.public_key()}
ALGORITHM = -19  # Fully specified COSE Ed25519 algorithm (RFC 9864).
ID_PROFILE = "demo-sha256-tagged-sign1-empty-unprotected-v1"
RELATION = "demo:direct-coverage"


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sign(key, issuer, subject, iat, payload):
    # Protected kid=4; CWT Claims header 15; CWT iss=1, sub=2, iat=6.
    protected = encode({1: ALGORITHM, 3: "application/json", 4: KIDS[issuer],
                        15: {1: issuer, 2: subject, 6: iat}})
    body = json_bytes(payload)
    signature = key.sign(encode(["Signature1", protected, b"", body]))
    return encode(Tag(18, [protected, {}, body, signature]))


def fields(carrier):
    value = decode(carrier)
    if not isinstance(value, Tag) or value.number != 18:
        raise ValueError("This profile requires COSE_Sign1 tag 18")
    if not isinstance(value.value, list) or len(value.value) != 4:
        raise ValueError("Expected four COSE_Sign1 fields")
    protected, unprotected, payload, signature = value.value
    if not (isinstance(protected, bytes) and isinstance(unprotected, dict)
            and isinstance(payload, bytes) and isinstance(signature, bytes)):
        raise ValueError("Only embedded payload and byte signatures are supported")
    return protected, unprotected, payload, signature


def verify(carrier):
    protected, _, payload, signature = fields(carrier)
    headers = decode(protected)
    if headers[1] != ALGORITHM or headers[3] != "application/json":
        raise ValueError("Unexpected local algorithm or content type")
    claims = headers[15]
    # Local public-key pinning only; issuer authorization is not established.
    KEYS[(claims[1], headers[4])].verify(
        signature, encode(["Signature1", protected, b"", payload]))
    return claims, json.loads(payload)


def projection(carrier):
    """Empty the unsigned map, preserve p/payload/signature bstr contents exactly.

    Re-encode tag 18, four-item array and empty map with shortest definite-length
    encodings. This defines ONLY this fixture's identity profile, not universal
    byte identity for every valid COSE serialization.
    """
    protected, _, payload, signature = fields(carrier)
    return encode(Tag(18, [protected, {}, payload, signature]))


def statement_id(carrier):
    return "sha256:" + hashlib.sha256(projection(carrier)).hexdigest()


def coverage(mode, targets):
    result = {"relation": RELATION, "id_profile": ID_PROFILE,
              "targets": targets}
    if mode is not None:
        result["mode"] = mode
    return result


def inspect_coverage(audit, target_id, available):
    """Membership in a signed declaration; never assess truth or sufficiency."""
    _, declaration = verify(audit)
    if declaration["relation"] != RELATION or declaration["id_profile"] != ID_PROFILE:
        raise ValueError("Unknown local relation or identity profile")
    mode = declaration.get("mode")
    if mode not in ("exact", "partial"):
        return "UNRESOLVED_COVERAGE_MODE"
    if target_id not in declaration["targets"]:
        return ("NOT_IN_DECLARED_COVERAGE" if mode == "exact"
                else "UNRESOLVED_UNLISTED_TARGET")
    if target_id not in available:
        return "DECLARED_MEMBER_UNAVAILABLE"
    target = available[target_id]
    if statement_id(target) != target_id:
        return "DECLARED_MEMBER_ID_MISMATCH"
    verify(target)
    return "DECLARED_MEMBER_AVAILABLE"


def rewrite_payload_keep_signature(carrier, replacement):
    protected, unsigned, _, signature = fields(carrier)
    return encode(Tag(18, [protected, unsigned, json_bytes(replacement), signature]))


def signature_rejects(carrier):
    try:
        verify(carrier)
    except InvalidSignature:
        return True
    return False


def run():
    checks = []

    def check(name, condition):
        if not condition:
            raise AssertionError(name)
        checks.append({"name": name, "passed": True})

    t = 1_790_000_000  # Fixed synthetic fixture time; no real event is asserted.
    s1 = sign(PRODUCER, PRODUCER_ISS, "urn:example:record:1", t,
              {"record": "S1", "value": "first input"})
    s2 = sign(PRODUCER, PRODUCER_ISS, "urn:example:record:2", t + 1,
              {"record": "S2", "value": "original second input"})
    ids = {"S1": statement_id(s1), "S2": statement_id(s2)}
    targets = [ids["S1"], ids["S2"]]
    a = sign(AUDITOR, AUDITOR_ISS, "urn:example:audit:A", t + 10,
             coverage("exact", targets))
    s3 = sign(PRODUCER, PRODUCER_ISS, "urn:example:record:2", t + 20,
              {"record": "S3", "value": "later correction",
               "correction_of": ids["S2"]})
    ids.update({"S3": statement_id(s3), "A": statement_id(a)})
    available = {ids["S1"]: s1, ids["S2"]: s2, ids["S3"]: s3, ids["A"]: a}
    for name, carrier in (("S1", s1), ("S2", s2), ("S3", s3), ("A", a)):
        claims, _ = verify(carrier)
        check(f"{name}_real_ed25519_signature_verifies", bool(claims))

    # Deliberately wrong resolver: substitute the latest record for an iss/sub.
    s2_claims, _ = verify(s2)
    candidates = [x for x in (s1, s2, s3)
                  if verify(x)[0][1] == s2_claims[1]
                  and verify(x)[0][2] == s2_claims[2]]
    naive = max(candidates, key=lambda x: verify(x)[0][6])
    naive_selected_id = statement_id(naive)
    check("same_iss_sub_latest_substitutes_S3", naive_selected_id == ids["S3"])
    correct_s2 = inspect_coverage(a, ids["S2"], available)
    correct_s3 = inspect_coverage(a, ids["S3"], available)
    check("exact_declaration_matches_available_S2", correct_s2 == "DECLARED_MEMBER_AVAILABLE")
    check("exact_declaration_excludes_S3", correct_s3 == "NOT_IN_DECLARED_COVERAGE")

    partial = sign(AUDITOR, AUDITOR_ISS, "urn:example:audit:partial", t + 10,
                   coverage("partial", targets))
    partial_s3 = inspect_coverage(partial, ids["S3"], available)
    check("partial_nonmembership_remains_unresolved", partial_s3 == "UNRESOLVED_UNLISTED_TARGET")
    missing_mode = sign(AUDITOR, AUDITOR_ISS, "urn:example:audit:no-mode", t + 10,
                        coverage(None, targets))
    unknown_mode = sign(AUDITOR, AUDITOR_ISS, "urn:example:audit:unknown-mode", t + 10,
                        coverage("unrecognized", targets))
    for label, carrier in (("missing", missing_mode), ("unknown", unknown_mode)):
        check(f"{label}_mode_remains_unresolved",
              inspect_coverage(carrier, ids["S3"], available) == "UNRESOLVED_COVERAGE_MODE")

    missing_store = {k: v for k, v in available.items() if k != ids["S2"]}
    missing_s2 = inspect_coverage(a, ids["S2"], missing_store)
    check("missing_declared_target_is_unavailable_not_excluded",
          missing_s2 == "DECLARED_MEMBER_UNAVAILABLE")

    changed_digest = coverage("exact", [ids["S1"], "sha256:" + "0" * 64])
    appended_target = coverage("exact", targets + [ids["S3"]])
    changed_mode = coverage("partial", targets)
    for label, changed in (("digest", changed_digest), ("list", appended_target),
                           ("mode", changed_mode)):
        check(f"tampered_{label}_fails_audit_signature",
              signature_rejects(rewrite_payload_keep_signature(a, changed)))

    altered_s2 = rewrite_payload_keep_signature(s2, {"record": "S2", "value": "tampered"})
    bad_store = dict(available, **{ids["S2"]: altered_s2})
    check("changed_target_bytes_fail_id_binding",
          inspect_coverage(a, ids["S2"], bad_store) == "DECLARED_MEMBER_ID_MISMATCH")
    check("changed_target_payload_fails_signature", signature_rejects(altered_s2))

    protected, _, payload, signature = fields(s2)
    # These are arbitrary unsigned metadata, NOT TS receipts or registrations.
    carrier_x = encode(Tag(18, [protected, {"demo-unsigned-carrier": "placeholder-X"},
                               payload, signature]))
    carrier_y = encode(Tag(18, [protected, {"demo-unsigned-carrier": "placeholder-Y"},
                               payload, signature]))
    raw_hashes = [hashlib.sha256(x).hexdigest() for x in (s2, carrier_x, carrier_y)]
    check("unsigned_carrier_metadata_changes_raw_hash", len(set(raw_hashes)) == 3)
    check("unsigned_carrier_metadata_preserves_profile_id",
          statement_id(s2) == statement_id(carrier_x) == statement_id(carrier_y))
    check("unsigned_carrier_metadata_preserves_signature",
          verify(carrier_x) == verify(s2) == verify(carrier_y))

    a_protected, _, a_payload, a_signature = fields(a)
    fake_unsigned_coverage = encode(Tag(18, [a_protected,
        {"demo-unsigned-coverage": coverage("exact", targets + [ids["S3"]])},
        a_payload, a_signature]))
    check("unsigned_coverage_substitution_leaves_signature_valid",
          verify(fake_unsigned_coverage) == verify(a))
    check("evaluator_ignores_unsigned_coverage_substitution",
          inspect_coverage(fake_unsigned_coverage, ids["S3"], available)
          == "NOT_IN_DECLARED_COVERAGE")

    # Indefinite-length outer array is valid generic CBOR but outside this profile.
    alternate = b"\xd2\x9f" + s2[2:] + b"\xff"
    try:
        fields(alternate)
    except ValueError:
        alternate_rejected = True
    else:
        alternate_rejected = False
    check("alternate_indefinite_outer_encoding_is_out_of_profile", alternate_rejected)

    b = sign(AUDITOR, AUDITOR_ISS, "urn:example:audit:B", t + 30,
             coverage("exact", [ids["A"]]))
    direct_a = inspect_coverage(b, ids["A"], available)
    transitive_s1 = inspect_coverage(b, ids["S1"], available)
    check("B_directly_lists_A", direct_a == "DECLARED_MEMBER_AVAILABLE")
    check("B_does_not_inherit_A_targets", transitive_s1 == "NOT_IN_DECLARED_COVERAGE")

    return {
        "scope": "Local reproducible synthetic fixture, not a deployed SCITT implementation",
        "cryptography": {"algorithm": "Ed25519", "cose_algorithm": ALGORITHM,
                         "version": version("cryptography"),
                         "keys": "Fixed public TEST-ONLY seeds 0x11*32 and 0x22*32",
                         "public_keys_hex": {
                             f"{iss} | kid={kid.decode()}": key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
                             for (iss, kid), key in KEYS.items()}},
        "identity_profile": ID_PROFILE,
        "statement_ids": ids,
        "failure_mode": {"same_iss_sub": True, "later_iat": True,
                         "naive_replacement": "S3", "naive_selected_id": naive_selected_id,
                         "exact_coverage_result": correct_s3},
        "membership_results": {"exact_S2": correct_s2, "exact_S3": correct_s3,
                               "partial_S3": partial_s3, "exact_S2_unavailable": missing_s2,
                               "missing_or_unknown_mode": "UNRESOLVED_COVERAGE_MODE",
                               "B_direct_A": direct_a, "B_transitive_S1": transitive_s1},
        "unsigned_carrier_experiment": {
            "description": "Arbitrary unsigned metadata placeholders; no TS receipts or registrations",
            "raw_sha256": raw_hashes, "stable_projected_id": ids["S2"]},
        "supported_claim": "Pinned-key signature authenticates an exact or partial direct-coverage declaration; local identifiers bind referenced record bytes",
        "unsupported_claims": ["Truth or adequacy of the audit", "Execution or outcome occurred",
                               "Issuer authority or identity beyond local key pinning",
                               "Records were received or retained by a required party",
                               "A missing record does not exist", "Global or time-bounded completeness",
                               "Verified TS registration, inclusion, time, consistency, or receipt validity",
                               "Coverage transfer through correction or other links",
                               "General SCITT, COSE, or CBOR conformance"],
        "checks_passed": len(checks), "checks": checks,
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, help="Also write the result JSON to this path")
    args = parser.parse_args()
    result_text = json.dumps(run(), indent=2) + "\n"
    if args.out:
        args.out.write_text(result_text, encoding="utf-8")
    print(result_text, end="")
