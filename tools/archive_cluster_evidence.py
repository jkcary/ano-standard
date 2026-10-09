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

from ano_runtime import IndependentClusterEvidenceVerifier, SchemaCatalog, WitnessedEvidenceLedger  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Verify and append witnessed ANO cluster evidence")
    parser.add_argument("--report", required=True)
    parser.add_argument("--envelope", required=True)
    parser.add_argument("--public-key", required=True, help="Pinned PEM Ed25519 witness public key")
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--witness-domain", required=True)
    parser.add_argument("--ledger", required=True)
    parser.add_argument("--expected-head", help="Externally anchored ledger head before append")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    loaded = serialization.load_pem_public_key(Path(args.public_key).read_bytes())
    if not isinstance(loaded, Ed25519PublicKey):
        raise TypeError("trusted witness key must be Ed25519")
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    verifier = IndependentClusterEvidenceVerifier(
        catalog, {args.key_id: (args.witness_domain, loaded)},
    )
    ledger = WitnessedEvidenceLedger(Path(args.ledger), catalog, verifier)
    if args.expected_head:
        ledger.verify(expected_head_hash=args.expected_head)
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    envelope = json.loads(Path(args.envelope).read_text(encoding="utf-8"))
    record = ledger.append(report, envelope)
    print(json.dumps({
        "record_id": record["record_id"], "sequence": record["sequence"],
        "ledger_head": ledger.head_hash(),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
