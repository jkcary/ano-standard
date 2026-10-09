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
    PolicyBoundClusterReportSourceVerifier, PolicyBoundTransparencyCheckpointVerifier,
    SchemaCatalog, TransparencyGossipMonitor,
)


def key_pairs(values: list[str], option: str) -> dict[str, Ed25519PublicKey]:
    result: dict[str, Ed25519PublicKey] = {}
    for value in values:
        key_id, separator, path = value.partition("=")
        if not separator or not key_id or key_id in result:
            raise ValueError(f"{option} must use a unique KEY_ID=PEM_PATH")
        key = serialization.load_pem_public_key(Path(path).read_bytes())
        if not isinstance(key, Ed25519PublicKey):
            raise TypeError(f"key must be Ed25519: {key_id}")
        result[key_id] = key
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify and gossip an ANO source transparency checkpoint")
    parser.add_argument("--checkpoint", required=True)
    parser.add_argument("--extension", required=True, help="JSON array of registry records after the previously accepted sequence")
    parser.add_argument("--state", required=True)
    parser.add_argument("--source-policy", required=True)
    parser.add_argument("--expected-source-policy-id", required=True)
    parser.add_argument("--minimum-source-policy-version", required=True, type=int)
    parser.add_argument("--expected-source-policy-hash", required=True)
    parser.add_argument("--trusted-source-key", required=True, action="append", metavar="KEY_ID=PEM_PATH")
    parser.add_argument("--log-policy", required=True)
    parser.add_argument("--expected-log-policy-id", required=True)
    parser.add_argument("--minimum-log-policy-version", required=True, type=int)
    parser.add_argument("--expected-log-policy-hash", required=True)
    parser.add_argument("--trusted-log-key", required=True, action="append", metavar="KEY_ID=PEM_PATH")
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    source_policy = json.loads(Path(args.source_policy).read_text(encoding="utf-8"))
    source_verifier = PolicyBoundClusterReportSourceVerifier(
        catalog, source_policy, key_pairs(args.trusted_source_key, "--trusted-source-key"),
        expected_policy_id=args.expected_source_policy_id,
        minimum_policy_version=args.minimum_source_policy_version,
        expected_policy_hash=args.expected_source_policy_hash,
    )
    log_policy = json.loads(Path(args.log_policy).read_text(encoding="utf-8"))
    checkpoint_verifier = PolicyBoundTransparencyCheckpointVerifier(
        catalog, log_policy, key_pairs(args.trusted_log_key, "--trusted-log-key"),
        expected_policy_id=args.expected_log_policy_id,
        minimum_policy_version=args.minimum_log_policy_version,
        expected_policy_hash=args.expected_log_policy_hash,
    )
    monitor = TransparencyGossipMonitor(args.state, catalog, checkpoint_verifier, source_verifier)
    checkpoint = json.loads(Path(args.checkpoint).read_text(encoding="utf-8"))
    extension = json.loads(Path(args.extension).read_text(encoding="utf-8"))
    if not isinstance(extension, list):
        raise TypeError("--extension must contain a JSON array")
    accepted = monitor.accept(checkpoint, extension)
    print(json.dumps({"status": "accepted", **{key: accepted[key] for key in ("log_id", "registry_id", "sequence", "head_hash")}}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
