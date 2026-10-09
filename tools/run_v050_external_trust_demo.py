from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_ROOT = ROOT / "reference" / "python"
if str(RUNTIME_ROOT) not in sys.path:
    sys.path.insert(0, str(RUNTIME_ROOT))

from ano_runtime import (  # noqa: E402
    ANOError, ArtifactProvenanceSigner, EdDsaJwksIssuer, ReferenceRemoteKmsProvider,
    SchemaCatalog, SqliteSecretLeaseBroker, SupplyChainPolicyVerifier,
    WorkloadIdentityVerifier, __version__, new_id, sha256_json, utc_now,
)
from run_conformance import implementation_source_hash  # noqa: E402


def run(path: Path, catalog: SchemaCatalog) -> dict[str, Any]:
    checks: list[dict[str, str]] = []

    def check(name: str, passed: bool, detail: str) -> None:
        checks.append({"check": name, "status": "passed" if passed else "failed", "detail": detail})

    now = datetime.now(timezone.utc).replace(microsecond=0)
    kms = ReferenceRemoteKmsProvider(
        catalog, allowed_callers={"runtime_alpha": {"tenant_data_key"}},
    )
    capabilities = kms.capabilities()
    check(
        "kms_capability_truthfulness",
        capabilities["runtime_verified"] and capabilities["remote_rewrap"]
        and not capabilities["remote_transport_verified"] and not capabilities["hsm_backed"],
        "reference KMS semantics are verified without claiming cloud transport or HSM backing",
    )
    context, plaintext_key = {"tenant_id": "tenant_alpha", "key_version": 1}, os.urandom(32)
    wrapped = kms.wrap_key(plaintext_key, context, purpose="tenant_data_key", caller="runtime_alpha")
    observed = "NO_ERROR"
    try:
        kms.unwrap_key(wrapped, context, purpose="tenant_data_key", caller="runtime_beta")
    except ANOError as exc:
        observed = exc.code
    check("kms_caller_purpose_binding", observed == "KMS_CALLER_DENIED", f"observed={observed}")
    kms.rotate()
    rewrapped, receipt = kms.rewrap_key(
        wrapped, context, purpose="tenant_data_key", caller="runtime_alpha",
    )
    check(
        "remote_rewrap",
        receipt["old_key_version"] == 1 and receipt["new_key_version"] == 2
        and kms.unwrap_key(rewrapped, context, purpose="tenant_data_key", caller="runtime_alpha") == plaintext_key,
        "rewrap preserved the DEK while replacing its master-key envelope",
    )

    oidc = EdDsaJwksIssuer("https://id.example.test")
    oidc_verifier = WorkloadIdentityVerifier(
        catalog, issuer=oidc.issuer, audience="ano-runtime", jwks=oidc.jwks(),
        replay_path=path.with_name("identity-replay.db"),
    )
    token = oidc.issue("workload_alpha", "ano-runtime", now=now)
    identity = oidc_verifier.verify(token, now=now)
    check("oidc_jwks_identity", identity["subject"] == "workload_alpha", "EdDSA JWKS token became a schema-valid workload identity")
    observed = "NO_ERROR"
    try:
        oidc_verifier.verify(token, now=now)
    except ANOError as exc:
        observed = exc.code
    check("identity_replay_rejection", observed == "IDENTITY_TOKEN_REPLAY", f"observed={observed}")
    oidc.rotate("identity_key_002")
    rotated_token = oidc.issue("workload_alpha", "ano-runtime", now=now)
    stale = "NO_ERROR"
    try:
        oidc_verifier.verify(rotated_token, now=now)
    except ANOError as exc:
        stale = exc.code
    oidc_verifier.refresh(oidc.jwks(include_retired=False))
    rotated_identity = oidc_verifier.verify(rotated_token, now=now)
    check(
        "jwks_rotation",
        stale == "IDENTITY_KEY_UNTRUSTED" and rotated_identity["key_id"] == "identity_key_002",
        "unknown key failed closed until explicit JWKS refresh",
    )

    spiffe = EdDsaJwksIssuer("https://spire.example.test")
    svid = spiffe.issue(
        "spiffe://example.org/ns/prod/sa/ano", "ano-runtime", now=now,
        selectors={"namespace": "prod", "service_account": "ano"},
    )
    spiffe_verifier = WorkloadIdentityVerifier(
        catalog, issuer=spiffe.issuer, audience="ano-runtime", jwks=spiffe.jwks(),
        mode="spiffe", trust_domain="example.org",
    )
    spiffe_identity = spiffe_verifier.verify(svid, now=now)
    check(
        "spiffe_trust_domain",
        spiffe_identity["subject"].startswith("spiffe://example.org/")
        and spiffe_identity["selectors"]["namespace"] == "prod",
        "JWT-SVID subject and selectors were bound to the configured trust domain",
    )

    broker_key = os.urandom(32)
    broker = SqliteSecretLeaseBroker(path, catalog, broker_key, oidc_verifier)
    broker.put_secret(
        "secret_database", "database_connect", b"ephemeral-credential",
        allowed_subjects={"workload_alpha"}, allowed_audiences={"ano-runtime"},
    )
    lease = broker.issue(
        identity, "secret_database", purpose="database_connect", audience="ano-runtime", now=now,
    )
    material = broker.redeem(
        lease, identity, purpose="database_connect", audience="ano-runtime", now=now,
    )
    check("short_secret_lease", material == b"ephemeral-credential", "identity-bound lease redeemed encrypted material exactly once")
    second = broker.issue(
        identity, "secret_database", purpose="database_connect", audience="ano-runtime", now=now,
    )
    observed = "NO_ERROR"
    try:
        broker.redeem(second, identity, purpose="artifact_sign", audience="ano-runtime", now=now)
    except ANOError as exc:
        observed = exc.code
    check("secret_purpose_binding", observed == "SECRET_LEASE_BINDING_MISMATCH", f"observed={observed}")
    event = broker.report_leak(second["lease_token"], now=now)
    restarted = SqliteSecretLeaseBroker(path, catalog, broker_key, oidc_verifier)
    observed = "NO_ERROR"
    try:
        restarted.redeem(second, identity, purpose="database_connect", audience="ano-runtime", now=now)
    except ANOError as exc:
        observed = exc.code
    check(
        "persistent_leak_revocation",
        event["lease_revoked"] and observed == "SECRET_LEASE_INACTIVE",
        "reported credential leak remained revoked after broker restart",
    )

    signer = ArtifactProvenanceSigner(catalog, "builder_alpha", "builder_key_001")
    artifact_hash = sha256_json({"artifact": "runtime-wheel"})
    sbom = {"format": "CycloneDX", "components": [{"name": "ano-runtime", "version": "0.5"}]}
    attestation = signer.attest(
        artifact_hash, sbom, source_uri="https://git.example.test/ano/runtime",
        source_commit="a" * 40, materials=[sha256_json({"dependency": "cryptography"})],
        invocation={"command": "python -m build", "network": "none"},
        isolated=True, reproducible=True, now=now,
    )
    policy = SupplyChainPolicyVerifier(
        catalog, {"builder_alpha": ("builder_key_001", signer.public_key)},
        allowed_source_prefixes=("https://git.example.test/ano/",),
    )
    decision = policy.verify(attestation, artifact_hash=artifact_hash, sbom=sbom, now=now)
    check(
        "signed_provenance_sbom",
        decision["status"] == "trusted" and decision["sbom_hash"] == sha256_json(sbom),
        "trusted builder signature bound artifact, immutable source, invocation, materials, and SBOM",
    )
    observed = "NO_ERROR"
    try:
        policy.verify(attestation, artifact_hash=sha256_json({"artifact": "substituted"}), sbom=sbom, now=now)
    except ANOError as exc:
        observed = exc.code
    check("artifact_substitution_rejection", observed == "SUPPLY_CHAIN_BINDING_MISMATCH", f"observed={observed}")
    check(
        "external_service_nonclaim", not capabilities["remote_transport_verified"],
        "no cloud KMS, HSM, enterprise OIDC, or SPIRE deployment certification is claimed",
    )
    return {
        "report_id": new_id("eta"), "schema_version": "0.5.0",
        "implementation_version": __version__, "implementation_source_hash": implementation_source_hash(),
        "generated_at": utc_now(), "status": "passed" if all(item["status"] == "passed" for item in checks) else "failed",
        "checks": checks, "verified_identity_id": identity["identity_id"],
        "secret_event_id": event["event_id"], "trust_decision_id": decision["decision_id"],
        "cloud_runtime_verified": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Run ANO 0.5 external trust plane acceptance")
    parser.add_argument("--output", default=str(ROOT / "reports" / "v050-external-trust-acceptance.json"))
    args = parser.parse_args()
    catalog = SchemaCatalog(ROOT / "schemas" / "v0.5.0")
    with tempfile.TemporaryDirectory() as directory_name:
        report = run(Path(directory_name) / "external-trust.db", catalog)
    catalog.validate("external-trust-acceptance-report", report)
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"status": report["status"], "checks": len(report["checks"]), "output": str(output)}, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
