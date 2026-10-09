from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    PolicyBoundClusterReportSourceVerifier, SchemaCatalog, create_cluster_evidence_envelope,
    sha256_json, utc_now,
)


MAX_SOURCE_BYTES = 2 * 1024 * 1024


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Independently fetch, verify and witness a signed ANO cluster report")
    parser.add_argument("--source-url", required=True)
    parser.add_argument("--expected-run-id", required=True)
    parser.add_argument("--source-policy", required=True)
    parser.add_argument("--expected-source-policy-id", required=True)
    parser.add_argument("--minimum-source-policy-version", required=True, type=int)
    parser.add_argument("--expected-source-policy-hash", required=True)
    parser.add_argument("--source-public-key", required=True)
    parser.add_argument("--source-key-id", required=True)
    parser.add_argument("--observer-private-key", required=True)
    parser.add_argument("--observer-key-id", required=True)
    parser.add_argument("--observer-domain", required=True)
    parser.add_argument("--runner-domain", required=True)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--previous-envelope-hash")
    parser.add_argument("--output", required=True)
    return parser.parse_args()


def is_loopback(host: str | None) -> bool:
    if host is None:
        return False
    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def main() -> int:
    args = parse_args()
    parsed = urllib.parse.urlparse(args.source_url)
    if parsed.scheme != "http" or not is_loopback(parsed.hostname):
        raise ValueError("Alpha.13 reference observer only permits loopback HTTP sources; production requires authenticated TLS")
    request_url = args.source_url.rstrip("/") + "/v1/reports/" + urllib.parse.quote(args.expected_run_id, safe="")
    with urllib.request.urlopen(request_url, timeout=10) as response:
        declared_length = response.headers.get("Content-Length")
        if declared_length is not None and int(declared_length) > MAX_SOURCE_BYTES:
            raise ValueError("report source response exceeds the 2 MiB limit")
        raw_response = response.read(MAX_SOURCE_BYTES + 1)
        if len(raw_response) > MAX_SOURCE_BYTES:
            raise ValueError("report source response exceeds the 2 MiB limit")
        result = json.loads(raw_response.decode("utf-8"))
    if not isinstance(result, dict) or set(result) != {"report", "source_envelope"}:
        raise ValueError("report source returned an invalid response")
    report, source_envelope = result["report"], result["source_envelope"]
    if report.get("run_id") != args.expected_run_id:
        raise ValueError("source returned an unexpected run identifier")
    source_key = serialization.load_pem_public_key(Path(args.source_public_key).read_bytes())
    if not isinstance(source_key, Ed25519PublicKey):
        raise TypeError("source public key must be Ed25519")
    source_policy = json.loads(Path(args.source_policy).read_text(encoding="utf-8"))
    source_verifier = PolicyBoundClusterReportSourceVerifier(
        SchemaCatalog(ROOT / "schemas" / "v0.3.0"), source_policy,
        {args.source_key_id: source_key}, expected_policy_id=args.expected_source_policy_id,
        minimum_policy_version=args.minimum_source_policy_version,
        expected_policy_hash=args.expected_source_policy_hash,
    )
    collected_at = utc_now()
    source_statement = source_verifier.verify_collected(report, source_envelope, collected_at=collected_at)
    observer_key = serialization.load_pem_private_key(Path(args.observer_private_key).read_bytes(), password=None)
    if not isinstance(observer_key, Ed25519PrivateKey):
        raise TypeError("observer private key must be Ed25519")
    observation = {
        "source_id": source_statement["source_id"], "source_domain": source_statement["source_domain"],
        "source_key_id": args.source_key_id, "source_envelope_hash": sha256_json(source_envelope),
        "acquisition_method": "direct-fetch-signed-source-v1", "collected_at": collected_at,
    }
    witness_envelope = create_cluster_evidence_envelope(
        report, observer_key, key_id=args.observer_key_id, runner_domain=args.runner_domain,
        witness_domain=args.observer_domain, witness_sequence=args.sequence,
        previous_envelope_hash=args.previous_envelope_hash, witnessed_at=utc_now(), observation=observation,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump({
            "report": report, "observer_envelope": witness_envelope,
            "source_envelope": source_envelope,
        }, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(output)
    print(json.dumps({"status": "observed", "run_id": report["run_id"], "source_id": source_statement["source_id"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
