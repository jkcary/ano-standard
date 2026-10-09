from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    IndependentWitnessQuorumVerifier, QuorumEvidenceLedger, SchemaCatalog, sha256_json,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify and append an ANO independent-witness quorum bundle")
    parser.add_argument("--report", required=True)
    parser.add_argument("--bundle", required=True)
    parser.add_argument("--trust-policy", required=True)
    parser.add_argument("--expected-trust-policy-id", required=True)
    parser.add_argument("--minimum-trust-policy-version", required=True, type=int)
    parser.add_argument("--expected-trust-policy-hash", required=True)
    parser.add_argument("--quorum-policy", required=True)
    parser.add_argument("--expected-quorum-policy-id", required=True)
    parser.add_argument("--minimum-quorum-policy-version", required=True, type=int)
    parser.add_argument("--expected-quorum-policy-hash", required=True)
    parser.add_argument(
        "--trusted-key", required=True, action="append", metavar="KEY_ID=PEM_PATH",
        help="Repeat once for every key referenced by the trust policy",
    )
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--initial-chain-heads", help="Pinned JSON member-chain heads when importing mid-chain")
    parser.add_argument("--expected-initial-chain-heads-hash", help="Pinned canonical JSON hash of imported chain heads")
    parser.add_argument("--expected-head", help="Externally anchored quorum-ledger head before append")
    return parser.parse_args()


def load_public_keys(values: list[str]) -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--trusted-key must use KEY_ID=PEM_PATH")
        key_id, path = value.split("=", 1)
        if not key_id or not path or key_id in keys:
            raise ValueError("trusted key identifier/path is empty or duplicated")
        loaded = serialization.load_pem_public_key(Path(path).read_bytes())
        if not isinstance(loaded, Ed25519PublicKey):
            raise TypeError(f"trusted witness key must be Ed25519: {key_id}")
        keys[key_id] = loaded
    return keys


def main() -> int:
    args = parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    trust_policy = json.loads(Path(args.trust_policy).read_text(encoding="utf-8"))
    quorum_policy = json.loads(Path(args.quorum_policy).read_text(encoding="utf-8"))
    verifier = IndependentWitnessQuorumVerifier(
        catalog, trust_policy, quorum_policy, load_public_keys(args.trusted_key),
        expected_trust_policy_id=args.expected_trust_policy_id,
        minimum_trust_policy_version=args.minimum_trust_policy_version,
        expected_trust_policy_hash=args.expected_trust_policy_hash,
        expected_quorum_policy_id=args.expected_quorum_policy_id,
        minimum_quorum_policy_version=args.minimum_quorum_policy_version,
        expected_quorum_policy_hash=args.expected_quorum_policy_hash,
    )
    if (args.initial_chain_heads is None) != (args.expected_initial_chain_heads_hash is None):
        raise ValueError("initial chain heads and their expected hash must be supplied together")
    initial_heads = None
    if args.initial_chain_heads is not None:
        initial_heads = json.loads(Path(args.initial_chain_heads).read_text(encoding="utf-8"))
        if sha256_json(initial_heads) != args.expected_initial_chain_heads_hash:
            raise ValueError("initial chain heads do not match their configured integrity anchor")
    ledger = QuorumEvidenceLedger(
        args.ledger, catalog, verifier, initial_chain_heads=initial_heads,
    )
    if args.expected_head:
        ledger.verify(expected_head_hash=args.expected_head)
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    bundle = json.loads(Path(args.bundle).read_text(encoding="utf-8"))
    record = ledger.append(report, bundle)
    print(json.dumps({
        "record_id": record["record_id"], "sequence": record["sequence"],
        "ledger_head": ledger.head_hash(), "member_chain_heads": ledger.chain_heads(),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
