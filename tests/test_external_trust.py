from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ano_runtime import (
    ANOError, ArtifactProvenanceSigner, EdDsaJwksIssuer, ReferenceRemoteKmsProvider,
    RemoteKmsProvider, SchemaCatalog, SqliteSecretLeaseBroker, SupplyChainPolicyVerifier,
    WorkloadIdentityVerifier, sha256_json,
)

from tests.support import STANDARD_ROOT, conformance


class ExternalTrustPlaneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.5.0")
        self.now = datetime.now(timezone.utc).replace(microsecond=0)

    def kms(self) -> ReferenceRemoteKmsProvider:
        return ReferenceRemoteKmsProvider(
            self.catalog, allowed_callers={"runtime_alpha": {"tenant_data_key"}},
        )

    def oidc(self) -> tuple[EdDsaJwksIssuer, WorkloadIdentityVerifier]:
        issuer = EdDsaJwksIssuer("https://id.example.test")
        verifier = WorkloadIdentityVerifier(
            self.catalog, issuer=issuer.issuer, audience="ano-runtime", jwks=issuer.jwks(),
        )
        return issuer, verifier

    def provenance(self, *, isolated: bool = True, reproducible: bool = True, source_commit: str | None = None):
        signer = ArtifactProvenanceSigner(self.catalog, "builder_alpha", "builder_key_001")
        sbom = {"format": "CycloneDX", "components": [{"name": "ano-runtime", "version": "0.5"}]}
        artifact_hash = sha256_json({"artifact": "runtime-wheel"})
        attestation = signer.attest(
            artifact_hash, sbom, source_uri="https://git.example.test/ano/runtime",
            source_commit=source_commit or "a" * 40,
            materials=[sha256_json({"dependency": "cryptography"})],
            invocation={"command": "python -m build", "network": "none"},
            isolated=isolated, reproducible=reproducible, now=self.now,
        )
        policy = SupplyChainPolicyVerifier(
            self.catalog, {"builder_alpha": ("builder_key_001", signer.public_key)},
            allowed_source_prefixes=("https://git.example.test/ano/",),
        )
        return signer, policy, sbom, artifact_hash, attestation

    @conformance("T-KMS-001")
    def test_remote_kms_contract_is_truthful_about_cloud_and_hsm_boundary(self) -> None:
        kms = self.kms()
        self.assertIsInstance(kms, RemoteKmsProvider)
        capabilities = kms.capabilities()
        self.assertTrue(capabilities["runtime_verified"])
        self.assertTrue(capabilities["purpose_binding"])
        self.assertTrue(capabilities["non_exportable_master_key"])
        self.assertFalse(capabilities["remote_transport_verified"])
        self.assertFalse(capabilities["hsm_backed"])

    @conformance("T-KMS-002")
    def test_kms_rejects_caller_purpose_context_and_ciphertext_substitution(self) -> None:
        kms, key = self.kms(), os.urandom(32)
        context = {"tenant_id": "tenant_alpha", "key_version": 1}
        envelope = kms.wrap_key(key, context, purpose="tenant_data_key", caller="runtime_alpha")
        self.assertEqual(key, kms.unwrap_key(envelope, context, purpose="tenant_data_key", caller="runtime_alpha"))
        cases = [
            ("runtime_beta", "tenant_data_key", context, "KMS_CALLER_DENIED"),
            ("runtime_alpha", "signing_key", context, "KMS_CALLER_DENIED"),
            ("runtime_alpha", "tenant_data_key", {"tenant_id": "tenant_beta", "key_version": 1}, "KMS_BINDING_MISMATCH"),
        ]
        for caller, purpose, supplied_context, code in cases:
            with self.subTest(code=code), self.assertRaises(ANOError) as observed:
                kms.unwrap_key(envelope, supplied_context, purpose=purpose, caller=caller)
            self.assertEqual(code, observed.exception.code)
        tampered = copy.deepcopy(envelope)
        tampered["ciphertext"] = tampered["ciphertext"][:-4] + "AAAA"
        with self.assertRaises(ANOError) as observed:
            kms.unwrap_key(tampered, context, purpose="tenant_data_key", caller="runtime_alpha")
        self.assertEqual("KMS_UNWRAP_FAILED", observed.exception.code)

    @conformance("T-KMS-003")
    def test_remote_rewrap_preserves_plaintext_and_binds_old_and_new_envelopes(self) -> None:
        kms, key = self.kms(), os.urandom(32)
        context = {"tenant_id": "tenant_alpha", "key_version": 1}
        original = kms.wrap_key(key, context, purpose="tenant_data_key", caller="runtime_alpha")
        kms.rotate()
        replacement, receipt = kms.rewrap_key(
            original, context, purpose="tenant_data_key", caller="runtime_alpha",
        )
        self.assertEqual(1, receipt["old_key_version"])
        self.assertEqual(2, receipt["new_key_version"])
        self.assertEqual(sha256_json(original), receipt["old_envelope_hash"])
        self.assertEqual(sha256_json(replacement), receipt["new_envelope_hash"])
        self.assertEqual(key, kms.unwrap_key(replacement, context, purpose="tenant_data_key", caller="runtime_alpha"))

    @conformance("T-OIDC-001")
    def test_oidc_jwks_verification_rejects_replay_algorithm_attack_and_stale_keys(self) -> None:
        issuer, verifier = self.oidc()
        token = issuer.issue("workload_alpha", "ano-runtime", now=self.now)
        identity = verifier.verify(token, now=self.now)
        self.assertEqual("workload_alpha", identity["subject"])
        with self.assertRaises(ANOError) as replay:
            verifier.verify(token, now=self.now)
        self.assertEqual("IDENTITY_TOKEN_REPLAY", replay.exception.code)
        parts = token.split(".")
        malicious_header = json.dumps({"alg": "none", "typ": "JWT", "kid": issuer.key_id}, separators=(",", ":")).encode()
        attacked = f"{self._b64(malicious_header)}.{parts[1]}.{parts[2]}"
        with self.assertRaises(ANOError) as algorithm:
            verifier.verify(attacked, now=self.now)
        self.assertEqual("IDENTITY_ALGORITHM_DENIED", algorithm.exception.code)
        issuer.rotate("identity_key_002")
        rotated = issuer.issue("workload_alpha", "ano-runtime", now=self.now)
        with self.assertRaises(ANOError) as stale:
            verifier.verify(rotated, now=self.now)
        self.assertEqual("IDENTITY_KEY_UNTRUSTED", stale.exception.code)
        verifier.refresh(issuer.jwks(include_retired=False))
        self.assertEqual("identity_key_002", verifier.verify(rotated, now=self.now)["key_id"])
        with tempfile.TemporaryDirectory() as directory_name:
            replay_path = Path(directory_name) / "identity-replay.db"
            persistent_token = issuer.issue("workload_alpha", "ano-runtime", now=self.now)
            first = WorkloadIdentityVerifier(
                self.catalog, issuer=issuer.issuer, audience="ano-runtime",
                jwks=issuer.jwks(include_retired=False), replay_path=replay_path,
            )
            first.verify(persistent_token, now=self.now)
            restarted = WorkloadIdentityVerifier(
                self.catalog, issuer=issuer.issuer, audience="ano-runtime",
                jwks=issuer.jwks(include_retired=False), replay_path=replay_path,
            )
            with self.assertRaises(ANOError) as persistent_replay:
                restarted.verify(persistent_token, now=self.now)
            self.assertEqual("IDENTITY_TOKEN_REPLAY", persistent_replay.exception.code)

    @staticmethod
    def _b64(value: bytes) -> str:
        import base64
        return base64.urlsafe_b64encode(value).decode().rstrip("=")

    @conformance("T-SPIFFE-001")
    def test_spiffe_identity_is_bound_to_trust_domain_and_workload_selectors(self) -> None:
        issuer = EdDsaJwksIssuer("https://spire.example.test")
        token = issuer.issue(
            "spiffe://example.org/ns/prod/sa/ano", "ano-runtime", now=self.now,
            selectors={"namespace": "prod", "service_account": "ano"},
        )
        verifier = WorkloadIdentityVerifier(
            self.catalog, issuer=issuer.issuer, audience="ano-runtime", jwks=issuer.jwks(),
            mode="spiffe", trust_domain="example.org",
        )
        identity = verifier.verify(token, now=self.now)
        self.assertEqual("prod", identity["selectors"]["namespace"])
        wrong_domain = WorkloadIdentityVerifier(
            self.catalog, issuer=issuer.issuer, audience="ano-runtime", jwks=issuer.jwks(),
            mode="spiffe", trust_domain="other.example",
        )
        with self.assertRaises(ANOError) as mismatch:
            wrong_domain.verify(token, now=self.now)
        self.assertEqual("SPIFFE_TRUST_DOMAIN_MISMATCH", mismatch.exception.code)

    @conformance("T-SEC-001")
    def test_secret_lease_is_short_lived_purpose_audience_subject_and_redemption_bound(self) -> None:
        issuer, verifier = self.oidc()
        identity = verifier.verify(issuer.issue("workload_alpha", "ano-runtime", now=self.now), now=self.now)
        with tempfile.TemporaryDirectory() as directory_name:
            broker = SqliteSecretLeaseBroker(Path(directory_name) / "secrets.db", self.catalog, os.urandom(32), verifier)
            broker.put_secret(
                "secret_database", "database_connect", b"postgres://ephemeral",
                allowed_subjects={"workload_alpha"}, allowed_audiences={"ano-runtime"},
            )
            lease = broker.issue(identity, "secret_database", purpose="database_connect", audience="ano-runtime", now=self.now)
            self.assertEqual(b"postgres://ephemeral", broker.redeem(
                lease, identity, purpose="database_connect", audience="ano-runtime", now=self.now,
            ))
            with self.assertRaises(ANOError) as exhausted:
                broker.redeem(lease, identity, purpose="database_connect", audience="ano-runtime", now=self.now)
            self.assertEqual("SECRET_LEASE_EXHAUSTED", exhausted.exception.code)
            replacement = broker.issue(identity, "secret_database", purpose="database_connect", audience="ano-runtime", now=self.now)
            with self.assertRaises(ANOError) as rebound:
                broker.redeem(replacement, identity, purpose="artifact_sign", audience="ano-runtime", now=self.now)
            self.assertEqual("SECRET_LEASE_BINDING_MISMATCH", rebound.exception.code)
            forged = copy.deepcopy(identity)
            forged["subject"] = "workload_beta"
            with self.assertRaises(ANOError) as proof:
                broker.issue(forged, "secret_database", purpose="database_connect", audience="ano-runtime", now=self.now)
            self.assertEqual("IDENTITY_PROOF_INVALID", proof.exception.code)
            attacker = verifier.verify(issuer.issue("workload_beta", "ano-runtime", now=self.now), now=self.now)
            with self.assertRaises(ANOError) as denied:
                broker.issue(attacker, "secret_database", purpose="database_connect", audience="ano-runtime", now=self.now)
            self.assertEqual("SECRET_ACCESS_DENIED", denied.exception.code)

    @conformance("T-SEC-002")
    def test_revocation_and_leak_detection_persistently_disable_secret_lease(self) -> None:
        issuer, verifier = self.oidc()
        identity = verifier.verify(issuer.issue("workload_alpha", "ano-runtime", now=self.now), now=self.now)
        with tempfile.TemporaryDirectory() as directory_name:
            path, key = Path(directory_name) / "secrets.db", os.urandom(32)
            broker = SqliteSecretLeaseBroker(path, self.catalog, key, verifier)
            broker.put_secret(
                "secret_database", "database_connect", b"credential",
                allowed_subjects={"workload_alpha"}, allowed_audiences={"ano-runtime"},
            )
            revoked = broker.issue(identity, "secret_database", purpose="database_connect", audience="ano-runtime", now=self.now)
            broker.revoke(revoked["lease_id"])
            with self.assertRaises(ANOError) as inactive:
                broker.redeem(revoked, identity, purpose="database_connect", audience="ano-runtime", now=self.now)
            self.assertEqual("SECRET_LEASE_INACTIVE", inactive.exception.code)
            leaked = broker.issue(identity, "secret_database", purpose="database_connect", audience="ano-runtime", now=self.now)
            event = broker.report_leak(leaked["lease_token"], now=self.now)
            self.assertTrue(event["lease_revoked"])
            restarted = SqliteSecretLeaseBroker(path, self.catalog, key, verifier)
            with self.assertRaises(ANOError) as leaked_error:
                restarted.redeem(leaked, identity, purpose="database_connect", audience="ano-runtime", now=self.now)
            self.assertEqual("SECRET_LEASE_INACTIVE", leaked_error.exception.code)

    @conformance("T-SUP-001")
    def test_signed_provenance_binds_artifact_sbom_source_builder_and_materials(self) -> None:
        _, policy, sbom, artifact_hash, attestation = self.provenance()
        decision = policy.verify(attestation, artifact_hash=artifact_hash, sbom=sbom, now=self.now)
        self.assertEqual("trusted", decision["status"])
        self.assertEqual(sha256_json(attestation), decision["attestation_hash"])
        self.assertEqual(sha256_json(sbom), decision["sbom_hash"])

    @conformance("T-SUP-002")
    def test_supply_chain_policy_rejects_substitution_mutable_source_and_weak_build(self) -> None:
        _, policy, sbom, artifact_hash, attestation = self.provenance()
        with self.assertRaises(ANOError) as substituted:
            policy.verify(attestation, artifact_hash=sha256_json({"artifact": "trojan"}), sbom=sbom, now=self.now)
        self.assertEqual("SUPPLY_CHAIN_BINDING_MISMATCH", substituted.exception.code)
        with self.assertRaises(ANOError) as sbom_attack:
            policy.verify(attestation, artifact_hash=artifact_hash, sbom={"components": []}, now=self.now)
        self.assertEqual("SUPPLY_CHAIN_BINDING_MISMATCH", sbom_attack.exception.code)
        _, mutable_policy, mutable_sbom, mutable_hash, mutable = self.provenance(source_commit="mainbranch")
        with self.assertRaises(ANOError) as source:
            mutable_policy.verify(mutable, artifact_hash=mutable_hash, sbom=mutable_sbom, now=self.now)
        self.assertEqual("SUPPLY_CHAIN_SOURCE_MUTABLE", source.exception.code)
        _, weak_policy, weak_sbom, weak_hash, weak = self.provenance(isolated=False, reproducible=False)
        with self.assertRaises(ANOError) as isolation:
            weak_policy.verify(weak, artifact_hash=weak_hash, sbom=weak_sbom, now=self.now)
        self.assertEqual("SUPPLY_CHAIN_ISOLATION_REQUIRED", isolation.exception.code)

    @conformance("T-E2E-001")
    def test_one_command_external_trust_demo_emits_machine_valid_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            output = Path(directory_name) / "external-trust-acceptance.json"
            completed = subprocess.run(
                [sys.executable, str(STANDARD_ROOT / "tools" / "run_v050_external_trust_demo.py"), "--output", str(output)],
                cwd=STANDARD_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.catalog.validate("external-trust-acceptance-report", report)
            self.assertEqual("passed", report["status"])
            self.assertEqual(13, len(report["checks"]))
            self.assertFalse(report["cloud_runtime_verified"])


if __name__ == "__main__":
    unittest.main()
