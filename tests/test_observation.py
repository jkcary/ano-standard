from __future__ import annotations

import copy
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ano_runtime import (
    ANOError, IndependentObservationQuorumVerifier, IndependentWitnessQuorumVerifier,
    PolicyBoundClusterReportSourceVerifier, SchemaCatalog, create_cluster_evidence_envelope,
    create_cluster_evidence_quorum_bundle, create_cluster_report_source_envelope,
    PolicyBoundTransparencyCheckpointVerifier, sha256_json, SourceObservationRegistry,
    TransparencyGossipMonitor, witness_public_key_fingerprint,
)

from tests.support import STANDARD_ROOT, conformance, load_example
from tests.test_quorum_evidence import timestamp, trust_entry


def source_entry(
    key_id: str, key: Ed25519PrivateKey, source_id: str, domain: str, now: datetime, *,
    operator_domain: str | None = None, infrastructure_domain: str | None = None,
    upstream_ids: list[str] | None = None,
) -> dict:
    return {
        "source_id": source_id, "source_domain": domain, "key_id": key_id, "algorithm": "Ed25519",
        "operator_domain": operator_domain or f"operator_{source_id}",
        "infrastructure_domain": infrastructure_domain or f"infra_{source_id}",
        "upstream_ids": upstream_ids or [f"upstream_{source_id}"],
        "public_key_sha256": witness_public_key_fingerprint(key.public_key()), "status": "active",
        "valid_from": timestamp(now - timedelta(days=1)), "valid_until": timestamp(now + timedelta(days=1)),
        "revoked_at": None, "revocation_mode": "none",
    }


def observation_envelope(
    report: dict, observer_key: Ed25519PrivateKey, observer_key_id: str, observer_domain: str,
    source_envelope: dict, source_key_id: str, source_id: str, source_domain: str,
    collected_at: datetime, witnessed_at: datetime,
) -> dict:
    return create_cluster_evidence_envelope(
        report, observer_key, key_id=observer_key_id, runner_domain="cluster_lab_domain",
        witness_domain=observer_domain, witness_sequence=1, previous_envelope_hash=None,
        witnessed_at=timestamp(witnessed_at), observation={
            "source_id": source_id, "source_domain": source_domain, "source_key_id": source_key_id,
            "source_envelope_hash": sha256_json(source_envelope),
            "acquisition_method": "direct-fetch-signed-source-v1",
            "collected_at": timestamp(collected_at),
        },
    )


class IndependentObservationConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")

    def build_verifier(
        self, observer_keys: dict[str, Ed25519PrivateKey], source_keys: dict[str, Ed25519PrivateKey],
        source_policy: dict, quorum_policy: dict, trust_policy: dict,
    ) -> IndependentObservationQuorumVerifier:
        quorum = IndependentWitnessQuorumVerifier(
            self.catalog, trust_policy, quorum_policy,
            {key_id: key.public_key() for key_id, key in observer_keys.items()},
            expected_trust_policy_id=trust_policy["policy_id"], minimum_trust_policy_version=1,
            expected_trust_policy_hash=sha256_json(trust_policy),
            expected_quorum_policy_id=quorum_policy["policy_id"], minimum_quorum_policy_version=1,
            expected_quorum_policy_hash=sha256_json(quorum_policy),
        )
        sources = PolicyBoundClusterReportSourceVerifier(
            self.catalog, source_policy,
            {key_id: key.public_key() for key_id, key in source_keys.items()},
            expected_policy_id=source_policy["policy_id"], minimum_policy_version=1,
            expected_policy_hash=sha256_json(source_policy),
        )
        return IndependentObservationQuorumVerifier(self.catalog, quorum, sources)

    @conformance("S-OBS-001")
    def test_quorum_requires_verifiable_distinct_source_lineage(self) -> None:
        now = datetime.now(timezone.utc)
        source_time, collected_time, witnessed_time = now - timedelta(minutes=2), now - timedelta(minutes=1), now
        report = load_example("cluster-validation-report")
        observer_keys = {"observer_key_a": Ed25519PrivateKey.generate(), "observer_key_b": Ed25519PrivateKey.generate()}
        source_keys = {"source_key_a": Ed25519PrivateKey.generate(), "source_key_b": Ed25519PrivateKey.generate()}
        trust_policy = {
            "policy_id": "wtp_observe_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "keys": [
                trust_entry("observer_key_a", observer_keys["observer_key_a"], "observer_domain_a", now=now),
                trust_entry("observer_key_b", observer_keys["observer_key_b"], "observer_domain_b", now=now),
            ],
        }
        quorum_policy = {
            "policy_id": "wqp_observe_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "threshold": 2, "maximum_witness_spread_seconds": 300,
            "maximum_bundle_delay_seconds": 600, "required_member_ids": [], "members": [
                {"member_id": "observer_a", "witness_domain": "observer_domain_a", "key_ids": ["observer_key_a"]},
                {"member_id": "observer_b", "witness_domain": "observer_domain_b", "key_ids": ["observer_key_b"]},
            ],
        }
        source_policy = {
            "policy_id": "osp_observe_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "maximum_source_age_seconds": 3600, "sources": [
                source_entry("source_key_a", source_keys["source_key_a"], "sensor_a", "source_domain_a", now),
                source_entry("source_key_b", source_keys["source_key_b"], "sensor_b", "source_domain_b", now),
            ],
        }
        verifier = self.build_verifier(observer_keys, source_keys, source_policy, quorum_policy, trust_policy)
        source_a = create_cluster_report_source_envelope(
            report, source_keys["source_key_a"], key_id="source_key_a", source_id="sensor_a",
            source_domain="source_domain_a", issued_at=timestamp(source_time),
        )
        source_b = create_cluster_report_source_envelope(
            report, source_keys["source_key_b"], key_id="source_key_b", source_id="sensor_b",
            source_domain="source_domain_b", issued_at=timestamp(source_time),
        )
        observer_a = observation_envelope(
            report, observer_keys["observer_key_a"], "observer_key_a", "observer_domain_a",
            source_a, "source_key_a", "sensor_a", "source_domain_a", collected_time, witnessed_time,
        )
        observer_b = observation_envelope(
            report, observer_keys["observer_key_b"], "observer_key_b", "observer_domain_b",
            source_b, "source_key_b", "sensor_b", "source_domain_b", collected_time, witnessed_time,
        )
        bundle = create_cluster_evidence_quorum_bundle(
            report, [observer_a, observer_b], quorum_policy, created_at=timestamp(now),
            source_attestations=[
                {"observer_key_id": "observer_key_a", "source_envelope": source_a},
                {"observer_key_id": "observer_key_b", "source_envelope": source_b},
            ],
        )
        result = verifier.verify(report, bundle)
        self.assertEqual(["source_domain_a", "source_domain_b"], result["source_domains"])

        missing_lineage = copy.deepcopy(bundle)
        missing_lineage.pop("source_attestations")
        with self.assertRaises(ANOError) as missing:
            verifier.verify(report, missing_lineage)
        self.assertEqual("OBSERVATION_LINEAGE_MISSING", missing.exception.code)

        forged_source = create_cluster_report_source_envelope(
            report, Ed25519PrivateKey.generate(), key_id="source_key_b", source_id="sensor_b",
            source_domain="source_domain_b", issued_at=timestamp(source_time),
        )
        forged_observer_b = observation_envelope(
            report, observer_keys["observer_key_b"], "observer_key_b", "observer_domain_b",
            forged_source, "source_key_b", "sensor_b", "source_domain_b", collected_time, witnessed_time,
        )
        forged_bundle = create_cluster_evidence_quorum_bundle(
            report, [observer_a, forged_observer_b], quorum_policy, created_at=timestamp(now),
            source_attestations=[
                {"observer_key_id": "observer_key_a", "source_envelope": source_a},
                {"observer_key_id": "observer_key_b", "source_envelope": forged_source},
            ],
        )
        with self.assertRaises(ANOError) as forged:
            verifier.verify(report, forged_bundle)
        self.assertEqual("OBSERVATION_SOURCE_SIGNATURE_INVALID", forged.exception.code)

        stale_source_a = create_cluster_report_source_envelope(
            report, source_keys["source_key_a"], key_id="source_key_a", source_id="sensor_a",
            source_domain="source_domain_a", issued_at=timestamp(now - timedelta(hours=2)),
        )
        stale_observer_a = observation_envelope(
            report, observer_keys["observer_key_a"], "observer_key_a", "observer_domain_a",
            stale_source_a, "source_key_a", "sensor_a", "source_domain_a", collected_time, witnessed_time,
        )
        stale_bundle = create_cluster_evidence_quorum_bundle(
            report, [stale_observer_a, observer_b], quorum_policy, created_at=timestamp(now),
            source_attestations=[
                {"observer_key_id": "observer_key_a", "source_envelope": stale_source_a},
                {"observer_key_id": "observer_key_b", "source_envelope": source_b},
            ],
        )
        with self.assertRaises(ANOError) as stale:
            verifier.verify(report, stale_bundle)
        self.assertEqual("OBSERVATION_SOURCE_STALE", stale.exception.code)

        duplicate_source_policy = copy.deepcopy(source_policy)
        duplicate_source_policy["sources"][1]["source_domain"] = "source_domain_a"
        duplicate_source_b = create_cluster_report_source_envelope(
            report, source_keys["source_key_b"], key_id="source_key_b", source_id="sensor_b",
            source_domain="source_domain_a", issued_at=timestamp(source_time),
        )
        duplicate_observer_b = observation_envelope(
            report, observer_keys["observer_key_b"], "observer_key_b", "observer_domain_b",
            duplicate_source_b, "source_key_b", "sensor_b", "source_domain_a", collected_time, witnessed_time,
        )
        duplicate_verifier = self.build_verifier(
            observer_keys, source_keys, duplicate_source_policy, quorum_policy, trust_policy,
        )
        duplicate_bundle = create_cluster_evidence_quorum_bundle(
            report, [observer_a, duplicate_observer_b], quorum_policy, created_at=timestamp(now),
            source_attestations=[
                {"observer_key_id": "observer_key_a", "source_envelope": source_a},
                {"observer_key_id": "observer_key_b", "source_envelope": duplicate_source_b},
            ],
        )
        with self.assertRaises(ANOError) as duplicate:
            duplicate_verifier.verify(report, duplicate_bundle)
        self.assertEqual("OBSERVATION_SOURCE_DOMAIN_DUPLICATE", duplicate.exception.code)

    @conformance("S-INDEP-001")
    def test_distinct_urls_do_not_count_when_control_infrastructure_or_upstream_is_shared(self) -> None:
        now = datetime.now(timezone.utc)
        report = load_example("cluster-validation-report")
        observer_keys = {"observer_key_a": Ed25519PrivateKey.generate(), "observer_key_b": Ed25519PrivateKey.generate()}
        source_keys = {"source_key_a": Ed25519PrivateKey.generate(), "source_key_b": Ed25519PrivateKey.generate()}
        trust_policy = {
            "policy_id": "wtp_independence_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "keys": [
                trust_entry("observer_key_a", observer_keys["observer_key_a"], "observer_domain_a", now=now),
                trust_entry("observer_key_b", observer_keys["observer_key_b"], "observer_domain_b", now=now),
            ],
        }
        quorum_policy = {
            "policy_id": "wqp_independence_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "threshold": 2, "maximum_witness_spread_seconds": 300,
            "maximum_bundle_delay_seconds": 600, "required_member_ids": [], "members": [
                {"member_id": "observer_a", "witness_domain": "observer_domain_a", "key_ids": ["observer_key_a"]},
                {"member_id": "observer_b", "witness_domain": "observer_domain_b", "key_ids": ["observer_key_b"]},
            ],
        }
        issued, collected = now - timedelta(minutes=2), now - timedelta(minutes=1)
        source_a = create_cluster_report_source_envelope(
            report, source_keys["source_key_a"], key_id="source_key_a", source_id="sensor_a",
            source_domain="source_domain_a", issued_at=timestamp(issued),
        )
        source_b = create_cluster_report_source_envelope(
            report, source_keys["source_key_b"], key_id="source_key_b", source_id="sensor_b",
            source_domain="source_domain_b", issued_at=timestamp(issued),
        )
        observer_a = observation_envelope(
            report, observer_keys["observer_key_a"], "observer_key_a", "observer_domain_a",
            source_a, "source_key_a", "sensor_a", "source_domain_a", collected, now,
        )
        observer_b = observation_envelope(
            report, observer_keys["observer_key_b"], "observer_key_b", "observer_domain_b",
            source_b, "source_key_b", "sensor_b", "source_domain_b", collected, now,
        )
        bundle = create_cluster_evidence_quorum_bundle(
            report, [observer_a, observer_b], quorum_policy, created_at=timestamp(now),
            source_attestations=[
                {"observer_key_id": "observer_key_a", "source_envelope": source_a},
                {"observer_key_id": "observer_key_b", "source_envelope": source_b},
            ],
        )
        base_entries = [
            source_entry("source_key_a", source_keys["source_key_a"], "sensor_a", "source_domain_a", now),
            source_entry("source_key_b", source_keys["source_key_b"], "sensor_b", "source_domain_b", now),
        ]
        cases = [
            ("upstream_ids", ["shared_audit_root"], "OBSERVATION_COMMON_UPSTREAM"),
            ("operator_domain", "shared_operator_domain", "OBSERVATION_COMMON_OPERATOR"),
            ("infrastructure_domain", "shared_infrastructure_domain", "OBSERVATION_COMMON_INFRASTRUCTURE"),
        ]
        for field, shared_value, expected_code in cases:
            with self.subTest(field=field):
                entries = copy.deepcopy(base_entries)
                entries[0][field] = copy.deepcopy(shared_value)
                entries[1][field] = copy.deepcopy(shared_value)
                policy = {
                    "policy_id": f"osp_shared_{field}", "schema_version": "0.3.0", "policy_version": 1,
                    "issued_at": timestamp(now), "maximum_source_age_seconds": 3600, "sources": entries,
                }
                verifier = self.build_verifier(observer_keys, source_keys, policy, quorum_policy, trust_policy)
                with self.assertRaises(ANOError) as shared:
                    verifier.verify(report, bundle)
                self.assertEqual(expected_code, shared.exception.code)

    @conformance("S-EQUIV-001")
    def test_source_registry_persists_signed_equivocation_and_detects_tamper_or_truncation(self) -> None:
        now = datetime.now(timezone.utc)
        source_key = Ed25519PrivateKey.generate()
        policy = {
            "policy_id": "osp_registry_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "maximum_source_age_seconds": 3600,
            "sources": [source_entry("source_key_registry", source_key, "sensor_registry", "source_domain_registry", now)],
        }
        verifier = PolicyBoundClusterReportSourceVerifier(
            self.catalog, policy, {"source_key_registry": source_key.public_key()},
            expected_policy_id="osp_registry_001", minimum_policy_version=1,
            expected_policy_hash=sha256_json(policy),
        )
        first_report = load_example("cluster-validation-report")
        forked_report = copy.deepcopy(first_report)
        forked_report["scenarios"][0]["evidence"] = "source presented a conflicting signed rollout"
        first_envelope = create_cluster_report_source_envelope(
            first_report, source_key, key_id="source_key_registry", source_id="sensor_registry",
            source_domain="source_domain_registry", issued_at=timestamp(now),
        )
        forked_envelope = create_cluster_report_source_envelope(
            forked_report, source_key, key_id="source_key_registry", source_id="sensor_registry",
            source_domain="source_domain_registry", issued_at=timestamp(now),
        )
        with tempfile.TemporaryDirectory() as directory_name:
            path = Path(directory_name) / "source-observations.jsonl"
            registry = SourceObservationRegistry(path, self.catalog, verifier)
            first_record = registry.append(first_report, first_envelope)
            self.assertEqual(first_record, registry.append(first_report, first_envelope))
            self.assertEqual(1, len(registry.records()))

            lock_path = path.with_suffix(path.suffix + ".lock")
            lock_path.write_text("other-writer", encoding="utf-8")
            with self.assertRaises(ANOError) as concurrent:
                registry.append(forked_report, forked_envelope)
            self.assertEqual("SOURCE_REGISTRY_CONCURRENT_WRITE", concurrent.exception.code)
            lock_path.unlink()

            with self.assertRaises(ANOError) as equivocation:
                registry.append(forked_report, forked_envelope)
            self.assertEqual("SOURCE_EQUIVOCATION_DETECTED", equivocation.exception.code)
            self.assertEqual(2, len(registry.records()))
            conflict_record = registry.records()[1]
            self.assertEqual("equivocation", conflict_record["verdict"])
            self.assertEqual(first_record["record_id"], conflict_record["conflicts_with_record_id"])
            anchored_head = registry.head_hash()
            reopened = SourceObservationRegistry(path, self.catalog, verifier)
            reopened.verify(expected_head_hash=anchored_head)

            original_lines = path.read_text(encoding="utf-8").splitlines()
            tampered = original_lines[0].replace("service account token absent", "tampered source observation")
            self.assertNotEqual(original_lines[0], tampered)
            path.write_text(tampered + "\n" + original_lines[1] + "\n", encoding="utf-8")
            with self.assertRaises(ANOError) as corrupt:
                SourceObservationRegistry(path, self.catalog, verifier)
            self.assertEqual("SOURCE_REGISTRY_CORRUPT", corrupt.exception.code)

            path.write_text(original_lines[0] + "\n", encoding="utf-8")
            truncated = SourceObservationRegistry(path, self.catalog, verifier)
            with self.assertRaises(ANOError) as rollback:
                truncated.verify(expected_head_hash=anchored_head)
            self.assertEqual("SOURCE_REGISTRY_TRUNCATED", rollback.exception.code)

    @conformance("S-GOSSIP-001")
    def test_signed_checkpoints_prove_consistent_growth_and_expose_split_views(self) -> None:
        now = datetime.now(timezone.utc)
        source_key = Ed25519PrivateKey.generate()
        log_key = Ed25519PrivateKey.generate()
        source_policy = {
            "policy_id": "osp_gossip_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "maximum_source_age_seconds": 3600,
            "sources": [source_entry("source_key_gossip", source_key, "sensor_gossip", "source_domain_gossip", now)],
        }
        source_verifier = PolicyBoundClusterReportSourceVerifier(
            self.catalog, source_policy, {"source_key_gossip": source_key.public_key()},
            expected_policy_id="osp_gossip_001", minimum_policy_version=1,
            expected_policy_hash=sha256_json(source_policy),
        )
        log_policy = {
            "policy_id": "tlp_gossip_001", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "logs": [{
                "log_id": "source_log_primary", "registry_id": "source_registry_primary",
                "operator_domain": "transparency_operator_primary", "key_id": "transparency_key_primary",
                "algorithm": "Ed25519", "public_key_sha256": witness_public_key_fingerprint(log_key.public_key()),
                "status": "active", "valid_from": timestamp(now - timedelta(days=1)),
                "valid_until": timestamp(now + timedelta(days=1)), "revoked_at": None,
                "revocation_mode": "none",
            }],
        }
        checkpoint_verifier = PolicyBoundTransparencyCheckpointVerifier(
            self.catalog, log_policy, {"transparency_key_primary": log_key.public_key()},
            expected_policy_id="tlp_gossip_001", minimum_policy_version=1,
            expected_policy_hash=sha256_json(log_policy),
        )
        report_one = load_example("cluster-validation-report")
        report_two = copy.deepcopy(report_one)
        report_two["run_id"] = "run_gossip_extension_002"
        envelope_one = create_cluster_report_source_envelope(
            report_one, source_key, key_id="source_key_gossip", source_id="sensor_gossip",
            source_domain="source_domain_gossip", issued_at=timestamp(now),
        )
        envelope_two = create_cluster_report_source_envelope(
            report_two, source_key, key_id="source_key_gossip", source_id="sensor_gossip",
            source_domain="source_domain_gossip", issued_at=timestamp(now),
        )
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            registry = SourceObservationRegistry(directory / "registry.jsonl", self.catalog, source_verifier)
            registry.append(report_one, envelope_one)
            checkpoint_one = registry.checkpoint(
                registry_id="source_registry_primary", log_id="source_log_primary",
                private_key=log_key, key_id="transparency_key_primary", issued_at=timestamp(now),
            )
            monitor = TransparencyGossipMonitor(
                directory / "gossip-state.json", self.catalog, checkpoint_verifier, source_verifier,
            )
            accepted_one = monitor.accept(checkpoint_one, registry.extension_since(0))
            self.assertEqual(1, accepted_one["sequence"])
            self.assertEqual(accepted_one, monitor.accept(checkpoint_one, []))

            registry.append(report_two, envelope_two)
            checkpoint_two = registry.checkpoint(
                registry_id="source_registry_primary", log_id="source_log_primary",
                private_key=log_key, key_id="transparency_key_primary", issued_at=timestamp(now),
            )
            accepted_two = monitor.accept(checkpoint_two, registry.extension_since(1))
            self.assertEqual(2, accepted_two["sequence"])
            reopened = TransparencyGossipMonitor(
                directory / "gossip-state.json", self.catalog, checkpoint_verifier, source_verifier,
            )
            self.assertEqual(2, reopened.entries()[0]["sequence"])
            anchored_state = reopened.state_hash()
            reopened.verify(expected_state_hash=anchored_state)
            with self.assertRaises(ANOError) as state_rollback:
                reopened.verify(expected_state_hash="sha256:" + "0" * 64)
            self.assertEqual("TRANSPARENCY_GOSSIP_STATE_ROLLBACK", state_rollback.exception.code)
            with self.assertRaises(ANOError) as rollback:
                reopened.accept(checkpoint_one, [])
            self.assertEqual("TRANSPARENCY_ROLLBACK", rollback.exception.code)

            forked_report = copy.deepcopy(report_one)
            forked_report["scenarios"][0]["evidence"] = "forked transparency view"
            forked_envelope = create_cluster_report_source_envelope(
                forked_report, source_key, key_id="source_key_gossip", source_id="sensor_gossip",
                source_domain="source_domain_gossip", issued_at=timestamp(now),
            )
            forked_registry = SourceObservationRegistry(directory / "fork.jsonl", self.catalog, source_verifier)
            forked_registry.append(forked_report, forked_envelope)
            forked_checkpoint = forked_registry.checkpoint(
                registry_id="source_registry_primary", log_id="source_log_primary",
                private_key=log_key, key_id="transparency_key_primary", issued_at=timestamp(now),
            )
            split_monitor = TransparencyGossipMonitor(
                directory / "split-state.json", self.catalog, checkpoint_verifier, source_verifier,
            )
            split_monitor.accept(checkpoint_one, registry.extension_since(0)[:1])
            with self.assertRaises(ANOError) as split_view:
                split_monitor.accept(forked_checkpoint, [])
            self.assertEqual("TRANSPARENCY_SPLIT_VIEW", split_view.exception.code)

            bad_extension = registry.extension_since(1)
            bad_extension[0]["previous_hash"] = forked_registry.head_hash()
            proof_monitor = TransparencyGossipMonitor(
                directory / "proof-state.json", self.catalog, checkpoint_verifier, source_verifier,
            )
            proof_monitor.accept(checkpoint_one, registry.extension_since(0)[:1])
            with self.assertRaises(ANOError) as invalid_proof:
                proof_monitor.accept(checkpoint_two, bad_extension)
            self.assertEqual("TRANSPARENCY_CONSISTENCY_PROOF_INVALID", invalid_proof.exception.code)

            invalid_log_policy = copy.deepcopy(log_policy)
            invalid_log_policy["logs"][0]["status"] = "revoked"
            with self.assertRaises(ANOError) as invalid_lifecycle:
                PolicyBoundTransparencyCheckpointVerifier(
                    self.catalog, invalid_log_policy, {"transparency_key_primary": log_key.public_key()},
                    expected_policy_id="tlp_gossip_001", minimum_policy_version=1,
                    expected_policy_hash=sha256_json(invalid_log_policy),
                )
            self.assertEqual("TRANSPARENCY_POLICY_INVALID", invalid_lifecycle.exception.code)


if __name__ == "__main__":
    unittest.main()
