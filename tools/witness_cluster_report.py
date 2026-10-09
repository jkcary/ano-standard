from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    DurableWitnessIssuer, SchemaCatalog, WitnessedEvidenceLedger,
)


def atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(value, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(path)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Sign a validated ANO cluster report from an independent witness boundary")
    parser.add_argument("--report", required=True)
    parser.add_argument("--private-key", required=True, help="PEM Ed25519 private key owned by the witness")
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--runner-domain", required=True)
    parser.add_argument("--witness-domain", required=True)
    parser.add_argument("--state", required=True, help="Witness-owned durable sequence state")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.runner_domain == args.witness_domain:
        raise ValueError("runner and witness domains must differ")
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    loaded = serialization.load_pem_private_key(Path(args.private_key).read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise TypeError("witness key must be Ed25519")
    issuer = DurableWitnessIssuer(
        args.state, catalog, loaded, key_id=args.key_id,
        runner_domain=args.runner_domain, witness_domain=args.witness_domain,
    )
    envelope = issuer.issue(report)
    status = issuer.status()
    envelope_hash = WitnessedEvidenceLedger.envelope_hash(envelope)
    atomic_json(Path(args.output), envelope)
    print(json.dumps({"sequence": status["sequence"], "envelope_hash": envelope_hash}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
