from __future__ import annotations

import argparse
import json
import os
import ipaddress
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    IndependentClusterEvidenceVerifier, PolicyBoundClusterEvidenceVerifier, SchemaCatalog,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Request and locally verify an ANO external witness envelope")
    parser.add_argument("--url", required=True)
    parser.add_argument("--token-file", required=True)
    parser.add_argument("--report", required=True)
    parser.add_argument("--public-key", required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--witness-domain", required=True)
    parser.add_argument("--expected-sequence", required=True, type=int)
    parser.add_argument("--expected-previous-hash")
    parser.add_argument("--ca-cert", help="PEM CA for the witness server certificate")
    parser.add_argument("--client-cert", help="PEM mTLS client certificate")
    parser.add_argument("--client-key", help="PEM mTLS client private key")
    parser.add_argument("--trust-policy", help="JSON witness key lifecycle policy")
    parser.add_argument("--expected-policy-id", help="Pinned witness policy identity")
    parser.add_argument("--minimum-policy-version", type=int, help="Pinned anti-rollback policy floor")
    parser.add_argument("--expected-policy-hash", help="Pinned canonical JSON hash of the trust policy")
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
    parsed = urllib.parse.urlparse(args.url)
    tls_values = (args.ca_cert, args.client_cert, args.client_key)
    if any(tls_values) and not all(tls_values):
        raise ValueError("--ca-cert, --client-cert and --client-key must be supplied together")
    context: ssl.SSLContext | None = None
    if parsed.scheme == "https":
        if not all(tls_values):
            raise ValueError("HTTPS witness requests require a CA and client certificate/key")
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=args.ca_cert)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=args.client_cert, keyfile=args.client_key)
    elif parsed.scheme == "http" and is_loopback(parsed.hostname):
        if any(tls_values):
            raise ValueError("TLS credentials cannot be used with plaintext HTTP")
    else:
        raise ValueError("plaintext witness requests are restricted to loopback; use authenticated TLS")
    token = Path(args.token_file).read_text(encoding="utf-8").strip()
    report = json.loads(Path(args.report).read_text(encoding="utf-8"))
    body = json.dumps({"report": report}, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        args.url.rstrip("/") + "/v1/witness", data=body, method="POST",
        headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(request, timeout=15, context=context) as response:
            result = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"witness service rejected request with HTTP {exc.code}: {detail}") from exc
    envelope = result["envelope"]
    loaded = serialization.load_pem_public_key(Path(args.public_key).read_bytes())
    if not isinstance(loaded, Ed25519PublicKey):
        raise TypeError("trusted witness key must be Ed25519")
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.3.0")
    policy_values = (
        args.trust_policy, args.expected_policy_id,
        args.minimum_policy_version, args.expected_policy_hash,
    )
    if any(value is not None for value in policy_values) and not all(value is not None for value in policy_values):
        raise ValueError("trust policy path, identity, version floor and hash must be supplied together")
    if all(value is not None for value in policy_values):
        policy = json.loads(Path(args.trust_policy).read_text(encoding="utf-8"))
        selected = next((item for item in policy.get("keys", []) if item.get("key_id") == args.key_id), None)
        if selected is None or selected.get("witness_domain") != args.witness_domain:
            raise ValueError("CLI witness identity does not match the selected trust-policy key")
        verifier = PolicyBoundClusterEvidenceVerifier(
            catalog, policy, {args.key_id: loaded},
            expected_policy_id=args.expected_policy_id,
            minimum_policy_version=args.minimum_policy_version,
            expected_policy_hash=args.expected_policy_hash,
        )
    else:
        verifier = IndependentClusterEvidenceVerifier(
            catalog, {args.key_id: (args.witness_domain, loaded)},
        )
    verifier.verify(
        report, envelope, expected_sequence=args.expected_sequence,
        expected_previous_envelope_hash=args.expected_previous_hash,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(envelope, handle, ensure_ascii=False, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(output)
    print(json.dumps({"status": "verified", "sequence": args.expected_sequence}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
