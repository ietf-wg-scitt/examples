#!/usr/bin/env python3
"""Offline inclusion-path check with nothing but the standard library.

Consumer: an auditor holds a 32-byte root and one inclusion path, has no
Transparency Service access, and does not want to install a COSE library. It
must answer one question: does this leaf belong to that tree?

The demo runs two readers over the same five vectors:

  strict  -- RFC 9162: leaf hash is SHA-256(0x00 || leaf_input), node hash is
             SHA-256(0x01 || left || right), largest-power-of-two split.
  naive   -- the same fold, but the leaf is hashed as SHA-256(leaf_input), i.e.
             the leaf-input digest is mistaken for the leaf hash.

The naive reader is the point of the demo. It is over-strict rather than
permissive: it rejects both honest proofs, so a verifier built that way
reports a failure for a tree that is intact.

No keys, no signatures, no receipts, no network access. Fixed inputs only.
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def leaf_hash(leaf_input: bytes) -> bytes:
    return sha256(LEAF_PREFIX + leaf_input)


def node_hash(left: bytes, right: bytes) -> bytes:
    return sha256(NODE_PREFIX + left + right)


def fold(leaf: bytes, index: int, size: int, path: list) -> bytes:
    """RFC 9162 section 2.1.3.2: fold the path over the leaf."""
    fn, sn = index, size - 1
    node = leaf
    for sibling in path:
        if fn & 1 or fn == sn:
            node = node_hash(sibling, node)
            while fn & 1 == 0 and fn != 0:
                fn >>= 1
                sn >>= 1
        else:
            node = node_hash(node, sibling)
        fn >>= 1
        sn >>= 1
    return node


def read_strict(vector: dict):
    leaf = leaf_hash(bytes.fromhex(vector["leaf_entry"]["leaf_input_hex"]))
    return fold(leaf, vector["leaf_index"], vector["tree_size"],
                [bytes.fromhex(p) for p in vector["inclusion_path"]])


def read_naive(vector: dict):
    leaf = sha256(bytes.fromhex(vector["leaf_entry"]["leaf_input_hex"]))
    return fold(leaf, vector["leaf_index"], vector["tree_size"],
                [bytes.fromhex(p) for p in vector["inclusion_path"]])


def verdict(vector: dict, root: bytes) -> str:
    return "VALID" if root == bytes.fromhex(vector["root_true"]) else "REJECT"


def run(directory: Path) -> dict:
    records = []
    for path in sorted(directory.glob("*.json")):
        vector = json.loads(path.read_text(encoding="utf-8"))
        expected = vector["result"]
        expected_valid = expected.upper() == "VALID"
        strict_root = read_strict(vector)
        naive_root = read_naive(vector)
        strict = verdict(vector, strict_root)
        naive = verdict(vector, naive_root)
        digest_ok = sha256(bytes.fromhex(vector["leaf_entry"]["leaf_input_hex"])) \
            == bytes.fromhex(vector["leaf_entry"]["digest_hex"])
        records.append({
            "vector": path.stem,
            "expected": expected,
            "leaf_input_digest_matches": digest_ok,
            "strict": strict,
            "strict_agrees": (strict == "VALID") == expected_valid,
            "naive": naive,
            "naive_agrees": (naive == "VALID") == expected_valid,
            "reconstructed_root": strict_root.hex(),
        })
    return {
        "vectors": len(records),
        "strict_agrees": sum(1 for r in records if r["strict_agrees"]),
        "naive_agrees": sum(1 for r in records if r["naive_agrees"]),
        "records": records,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--vectors", default=str(Path(__file__).resolve().parent.parent / "vectors"))
    parser.add_argument("--out", default="")
    args = parser.parse_args(argv)
    result = run(Path(args.vectors))
    text = json.dumps(result, indent=2, sort_keys=True)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    print(text)
    ok = result["strict_agrees"] == result["vectors"]
    print(f"\nstrict reader: {result['strict_agrees']}/{result['vectors']} agree with the expected verdict", file=sys.stderr)
    print(f"naive reader:  {result['naive_agrees']}/{result['vectors']} agree with the expected verdict", file=sys.stderr)
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
