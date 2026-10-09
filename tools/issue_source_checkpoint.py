from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import PolicyBoundClusterReportSourceVerifier, SchemaCatalog, SourceObservationRegistry  # noqa: E402


def key_pairs(values: list[str]) -> dict[str, Ed25519PublicKey]:
    result: dict[str, Ed25519PublicKey] = {}
    for value in values:
        key_id, separator, path = value.partition("=")
        if not separator or not key_id or key_id in result:
            raise ValueError("--trusted-source-key must use a unique KEY_ID=PEM_PATH")
        key = serialization.load_pem_public_key(Path(path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError(f"source key must be Ed25519: {key_id}")
        result[key_id] = key
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Issue a signed checkpoint for an ANO source registry")
    parser.add_argument("--registry", required=True)
    parser.add_argument("--registry-id", required=True)
    parser.add_argument("--log-id", required=True)
    parser.add_argument("--log-key-id", required=True)
    parser.add_argument("--log-private-key", required=True)
    parser.add_argument("--source-policy", required=True)
    parser.add_argument("--expected-source-policy-id", required=True)
    parser.add_argument("--minimum-source-policy-version", required=True, type=int)
    parser.add_argument("--expected-source-policy-hash", required=True)
    parser.add_argument("--trusted-source-key", required=True, action="append", metavar="KEY_ID=PEM_PATH")
    parser.add_argument("--output", required=True)
    parser.add_argument("--extension-output", help="Write the consistency proof records as a JSON array")
    parser.add_argument("--since", type=int, default=0, help="Previously accepted registry sequence")
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    policy = json.loads(Path(args.source_policy).read_text(encoding="utf-8"))
    source_verifier = PolicyBoundClusterReportSourceVerifier(
        catalog, policy, key_pairs(args.trusted_source_key),
        expected_policy_id=args.expected_source_policy_id,
        minimum_policy_version=args.minimum_source_policy_version,
        expected_policy_hash=args.expected_source_policy_hash,
    )
    registry = SourceObservationRegistry(args.registry, catalog, source_verifier)
    private_key = serialization.load_pem_private_key(Path(args.log_private_key).read_bytes(), password=None)
    if not isinstance(private_key, Ed25519PrivateKey):
        raise TypeError("transparency log private key must be Ed25519")
    envelope = registry.checkpoint(
        registry_id=args.registry_id, log_id=args.log_id, private_key=private_key,
        key_id=args.log_key_id,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(envelope, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.extension_output:
        extension_output = Path(args.extension_output)
        extension_output.parent.mkdir(parents=True, exist_ok=True)
        extension_output.write_text(
            json.dumps(registry.extension_since(args.since), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    print(json.dumps({"status": "issued", "sequence": len(registry.records()), "head_hash": registry.head_hash(), "output": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
