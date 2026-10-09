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
    ANOError, PolicyBoundClusterReportSourceVerifier, SchemaCatalog, SourceObservationRegistry,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Register source-signed reports and preserve equivocation evidence")
    parser.add_argument("--report", required=True)
    parser.add_argument("--source-envelope", required=True)
    parser.add_argument("--source-policy", required=True)
    parser.add_argument("--expected-policy-id", required=True)
    parser.add_argument("--minimum-policy-version", required=True, type=int)
    parser.add_argument("--expected-policy-hash", required=True)
    parser.add_argument("--trusted-key", required=True, action="append", metavar="KEY_ID=PEM_PATH")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--expected-head", help="Externally anchored registry head before append")
    return parser.parse_args()


def load_keys(values: list[str]) -> dict[str, Ed25519PublicKey]:
    keys: dict[str, Ed25519PublicKey] = {}
    for value in values:
        if "=" not in value:
            raise ValueError("--trusted-key must use KEY_ID=PEM_PATH")
        key_id, path = value.split("=", 1)
        if not key_id or not path or key_id in keys:
            raise ValueError("source key identifier/path is empty or duplicated")
        loaded = serialization.load_pem_public_key(Path(path).read_bytes())
        if not isinstance(loaded, Ed25519PublicKey):
            raise TypeError(f"source key must be Ed25519: {key_id}")
        keys[key_id] = loaded
    return keys


def main() -> int:
    args = parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    policy = json.loads(Path(args.source_policy).read_text(encoding="utf-8"))
    verifier = PolicyBoundClusterReportSourceVerifier(
        catalog, policy, load_keys(args.trusted_key), expected_policy_id=args.expected_policy_id,
        minimum_policy_version=args.minimum_policy_version, expected_policy_hash=args.expected_policy_hash,
    )
    registry = SourceObservationRegistry(args.registry, catalog, verifier)
    if args.expected_head:
        registry.verify(expected_head_hash=args.expected_head)
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    source_envelope = json.loads(Path(args.source_envelope).read_text(encoding="utf-8"))
    try:
        record = registry.append(report, source_envelope)
        status, exit_code = record["verdict"], 0
    except ANOError as exc:
        if exc.code != "SOURCE_EQUIVOCATION_DETECTED":
            raise
        record = registry.records()[-1]
        status, exit_code = "equivocation", 2
    print(json.dumps({
        "status": status, "record_id": record["record_id"], "sequence": record["sequence"],
        "conflicts_with_record_id": record["conflicts_with_record_id"],
        "registry_head": registry.head_hash(),
    }, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
