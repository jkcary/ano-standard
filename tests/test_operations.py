from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ano_runtime import (
    ANOError,
    Ed25519IdentityIssuer,
    SchemaCatalog,
    SqliteExternalIdentityVerifier,
    SqliteLeaseCoordinator,
    SqliteSloMonitor,
    SqliteTenantQuotaManager,
    TenantAccessBoundary,
)

from tests.support import STANDARD_ROOT, conformance


class ProductionOperationsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.4.0")
        self.boundary = TenantAccessBoundary(
            self.catalog,
            {"principal_alpha": "tenant_alpha", "principal_beta": "tenant_beta"},
            secret=b"alpha4-operations-boundary-secret-32-bytes-minimum",
        )
        self.now = datetime(2026, 1, 1, tzinfo=timezone.utc)

    @conformance("O-IDP-001")
    def test_external_signed_identity_is_verified_consumed_once_and_tenant_bound(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            issuer = Ed25519IdentityIssuer(self.catalog, "https://idp.example", "identity_key_001")
            verifier = SqliteExternalIdentityVerifier(
                Path(directory_name) / "identity.db", self.catalog, self.boundary,
                expected_issuer="https://idp.example", expected_audience="ano-runtime",
                trusted_keys={"identity_key_001": issuer.public_key},
            )
            assertion = issuer.issue("principal_alpha", "ano-runtime", now=self.now)
            session = verifier.verify_and_open(assertion, now=self.now + timedelta(seconds=1))
            self.assertEqual(("principal_alpha", "tenant_alpha"), (session.principal_id, session.tenant_id))
            with self.assertRaises(ANOError) as replay:
                verifier.verify_and_open(assertion, now=self.now + timedelta(seconds=2))
            self.assertEqual("IDENTITY_ASSERTION_REPLAY", replay.exception.code)

            changed = copy.deepcopy(issuer.issue("principal_beta", "ano-runtime", now=self.now))
            changed["subject"] = "principal_alpha"
            with self.assertRaises(ANOError) as forged:
                verifier.verify_and_open(changed, now=self.now + timedelta(seconds=1))
            self.assertEqual("IDENTITY_SIGNATURE_INVALID", forged.exception.code)
            wrong_audience = issuer.issue("principal_alpha", "different-runtime", now=self.now)
            with self.assertRaises(ANOError) as audience:
                verifier.verify_and_open(wrong_audience, now=self.now + timedelta(seconds=1))
            self.assertEqual("IDENTITY_TRUST_MISMATCH", audience.exception.code)

    @conformance("O-LEASE-001")
    def test_expired_lease_holder_is_fenced_by_monotonic_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            coordinator = SqliteLeaseCoordinator(Path(directory_name) / "coordination.db", self.catalog)
            first = coordinator.acquire("resource_alpha", "worker_alpha", ttl_seconds=5, now=self.now)
            self.assertEqual(1, first["fencing_token"])
            with self.assertRaises(ANOError) as busy:
                coordinator.acquire(
                    "resource_alpha", "worker_beta", ttl_seconds=5, now=self.now + timedelta(seconds=1),
                )
            self.assertEqual("LEASE_BUSY", busy.exception.code)
            second = coordinator.acquire(
                "resource_alpha", "worker_beta", ttl_seconds=5, now=self.now + timedelta(seconds=6),
            )
            self.assertEqual(2, second["fencing_token"])
            with self.assertRaises(ANOError) as fenced:
                coordinator.assert_fence(first, now=self.now + timedelta(seconds=6))
            self.assertEqual("LEASE_FENCE_REJECTED", fenced.exception.code)
            coordinator.assert_fence(second, now=self.now + timedelta(seconds=7))
            renewed = coordinator.renew(second, ttl_seconds=10, now=self.now + timedelta(seconds=7))
            coordinator.assert_fence(renewed, now=self.now + timedelta(seconds=15))
            coordinator.release(renewed)
            third = coordinator.acquire(
                "resource_alpha", "worker_alpha", ttl_seconds=5, now=self.now + timedelta(seconds=16),
            )
            self.assertEqual(3, third["fencing_token"])

    @conformance("O-QUOTA-001")
    def test_quota_consumption_is_atomic_idempotent_and_tenant_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            quota = SqliteTenantQuotaManager(Path(directory_name) / "quota.db", self.catalog)
            quota.configure("tenant_alpha", {"operations": 2, "model_tokens": 10}, window_seconds=60)
            quota.configure("tenant_beta", {"operations": 1, "model_tokens": 100}, window_seconds=60)
            first = quota.consume(
                "tenant_alpha", "operation_alpha_001", {"operations": 1, "model_tokens": 6}, now=self.now,
            )
            replay = quota.consume(
                "tenant_alpha", "operation_alpha_001", {"operations": 1, "model_tokens": 6}, now=self.now,
            )
            self.assertTrue(replay["idempotent_replay"])
            self.assertEqual(first["receipt_id"], replay["receipt_id"])
            with self.assertRaises(ANOError) as exceeded:
                quota.consume(
                    "tenant_alpha", "operation_alpha_002", {"operations": 1, "model_tokens": 5}, now=self.now,
                )
            self.assertEqual("QUOTA_EXCEEDED", exceeded.exception.code)
            accepted = quota.consume(
                "tenant_alpha", "operation_alpha_003", {"operations": 1, "model_tokens": 4}, now=self.now,
            )
            self.assertEqual({"operations": 2, "model_tokens": 10}, accepted["usage"])
            beta = quota.consume(
                "tenant_beta", "operation_beta_001", {"operations": 1, "model_tokens": 90}, now=self.now,
            )
            self.assertEqual(90, beta["usage"]["model_tokens"])

    @conformance("O-SLO-001")
    def test_slo_reports_are_windowed_and_tenant_scoped(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            monitor = SqliteSloMonitor(Path(directory_name) / "slo.db", self.catalog)
            for index in range(20):
                monitor.record(
                    "tenant_alpha", "runtime_api", success=index != 0,
                    latency_ms=50 + index, now=self.now + timedelta(seconds=index),
                )
            monitor.record(
                "tenant_beta", "runtime_api", success=False, latency_ms=5000,
                now=self.now + timedelta(seconds=10),
            )
            report = monitor.evaluate(
                "tenant_alpha", "runtime_api", window_seconds=60,
                availability_target=0.95, p95_latency_target_ms=70,
                now=self.now + timedelta(seconds=30),
            )
            self.assertEqual(20, report["sample_count"])
            self.assertEqual(0.95, report["availability"])
            self.assertEqual(68, report["p95_latency_ms"])
            self.assertEqual("met", report["status"])
            strict = monitor.evaluate(
                "tenant_alpha", "runtime_api", window_seconds=60,
                availability_target=0.99, p95_latency_target_ms=60,
                now=self.now + timedelta(seconds=30),
            )
            self.assertEqual("violated", strict["status"])

    @conformance("O-RC-001")
    def test_production_kernel_demo_emits_machine_valid_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            output = Path(directory_name) / "production-kernel.json"
            completed = subprocess.run(
                [sys.executable, str(STANDARD_ROOT / "tools" / "run_v040_rc_demo.py"), "--output", str(output)],
                cwd=STANDARD_ROOT, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.catalog.validate("production-kernel-report", report)
            self.assertEqual("passed", report["status"])
            self.assertEqual(11, len(report["checks"]))
            self.assertTrue(all(item["status"] == "passed" for item in report["checks"]))


if __name__ == "__main__":
    unittest.main()
