from __future__ import annotations

import copy
import json
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ano_runtime import (
    ANOError, IndependentObservationQuorumVerifier, IndependentWitnessQuorumVerifier,
    PolicyBoundClusterReportSourceVerifier, SchemaCatalog,
    create_cluster_evidence_quorum_bundle, sha256_json,
)

from tests.support import STANDARD_ROOT, conformance, load_example
from tests.test_observation import source_entry
from tests.test_quorum_evidence import timestamp, trust_entry


class IndependentObservationNetworkTests(unittest.TestCase):
    source_tool = STANDARD_ROOT / "tools" / "run_report_source_service.py"
    observer_tool = STANDARD_ROOT / "tools" / "observe_cluster_report.py"

    @staticmethod
    def stop(process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        else:
            process.communicate()

    @staticmethod
    def write_private(path: Path, key: Ed25519PrivateKey) -> None:
        path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))

    @staticmethod
    def write_public(path: Path, key: Ed25519PrivateKey) -> None:
        path.write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))

    def start_source(
        self, directory: Path, member: str, key: Ed25519PrivateKey, report: dict,
    ) -> tuple[subprocess.Popen[str], str, Path, Path]:
        report_path, key_path = directory / f"report-{member}.json", directory / f"source-{member}.pem"
        public_path, ready_path = directory / f"source-{member}.pub.pem", directory / f"source-{member}.ready.json"
        report_path.write_text(json.dumps(report), encoding="utf-8")
        self.write_private(key_path, key)
        self.write_public(public_path, key)
        process = subprocess.Popen([
            sys.executable, str(self.source_tool), "--report", str(report_path),
            "--private-key", str(key_path), "--key-id", f"source_key_{member}",
            "--source-id", f"sensor_{member}", "--source-domain", f"source_domain_{member}",
            "--port", "0", "--ready-file", str(ready_path),
        ], cwd=STANDARD_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if ready_path.exists():
                url = json.loads(ready_path.read_text(encoding="utf-8"))["url"]
                return process, url, public_path, report_path
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(f"source {member} failed to start: {stdout}\n{stderr}")
            time.sleep(0.05)
        self.stop(process)
        self.fail(f"source {member} startup timed out")

    def observe(
        self, directory: Path, member: str, url: str, source_public: Path,
        source_key: Ed25519PrivateKey, observer_key: Ed25519PrivateKey, now: datetime,
    ) -> subprocess.CompletedProcess[str]:
        observer_path = directory / f"observer-{member}.pem"
        policy_path, output_path = directory / f"source-policy-{member}.json", directory / f"observation-{member}.json"
        self.write_private(observer_path, observer_key)
        policy = {
            "policy_id": f"osp_member_{member}", "schema_version": "0.3.0", "policy_version": 1,
            "issued_at": timestamp(now), "maximum_source_age_seconds": 3600, "sources": [
                source_entry(f"source_key_{member}", source_key, f"sensor_{member}", f"source_domain_{member}", now),
            ],
        }
        policy_path.write_text(json.dumps(policy), encoding="utf-8")
        return subprocess.run([
            sys.executable, str(self.observer_tool), "--source-url", url,
            "--expected-run-id", "lab_demo_001", "--source-policy", str(policy_path),
            "--expected-source-policy-id", f"osp_member_{member}",
            "--minimum-source-policy-version", "1", "--expected-source-policy-hash", sha256_json(policy),
            "--source-public-key", str(source_public), "--source-key-id", f"source_key_{member}",
            "--observer-private-key", str(observer_path), "--observer-key-id", f"observer_key_{member}",
            "--observer-domain", f"observer_domain_{member}", "--runner-domain", "cluster_lab_domain",
            "--sequence", "1", "--output", str(output_path),
        ], cwd=STANDARD_ROOT, text=True, capture_output=True, timeout=20, check=False)

    @conformance("S-OSRC-001")
    def test_observers_fetch_independent_sources_and_reject_source_failure_or_divergence(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            base_report = load_example("cluster-validation-report")
            divergent_report = copy.deepcopy(base_report)
            divergent_report["scenarios"][0]["evidence"] = "divergent independently observed rollout"
            source_keys = {member: Ed25519PrivateKey.generate() for member in ("a", "b", "c")}
            observer_keys = {member: Ed25519PrivateKey.generate() for member in ("a", "b", "c")}
            sources: dict[str, tuple[subprocess.Popen[str], str, Path, Path]] = {}
            now = datetime.now(timezone.utc)
            try:
                sources["a"] = self.start_source(directory, "a", source_keys["a"], base_report)
                sources["b"] = self.start_source(directory, "b", source_keys["b"], base_report)
                sources["c"] = self.start_source(directory, "c", source_keys["c"], divergent_report)
                observations: dict[str, dict] = {}
                for member in ("a", "b", "c"):
                    result = self.observe(
                        directory, member, sources[member][1], sources[member][2],
                        source_keys[member], observer_keys[member], now,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                    observations[member] = json.loads((directory / f"observation-{member}.json").read_text(encoding="utf-8"))
                self.assertNotEqual(
                    sha256_json(observations["a"]["report"]), sha256_json(observations["c"]["report"]),
                )

                self.stop(sources["c"][0])
                unavailable = self.observe(
                    directory, "c", sources["c"][1], sources["c"][2],
                    source_keys["c"], observer_keys["c"], now,
                )
                self.assertNotEqual(0, unavailable.returncode)

                trust_policy = {
                    "policy_id": "wtp_observation_network", "schema_version": "0.3.0", "policy_version": 1,
                    "issued_at": timestamp(now), "keys": [
                        trust_entry(f"observer_key_{member}", observer_keys[member], f"observer_domain_{member}", now=now)
                        for member in ("a", "b", "c")
                    ],
                }
                quorum_policy = {
                    "policy_id": "wqp_observation_network", "schema_version": "0.3.0", "policy_version": 1,
                    "issued_at": timestamp(now), "threshold": 2, "maximum_witness_spread_seconds": 300,
                    "maximum_bundle_delay_seconds": 600, "required_member_ids": [], "members": [
                        {"member_id": f"observer_{member}", "witness_domain": f"observer_domain_{member}", "key_ids": [f"observer_key_{member}"]}
                        for member in ("a", "b", "c")
                    ],
                }
                source_policy = {
                    "policy_id": "osp_observation_network", "schema_version": "0.3.0", "policy_version": 1,
                    "issued_at": timestamp(now), "maximum_source_age_seconds": 3600, "sources": [
                        source_entry(f"source_key_{member}", source_keys[member], f"sensor_{member}", f"source_domain_{member}", now)
                        for member in ("a", "b", "c")
                    ],
                }
                quorum = IndependentWitnessQuorumVerifier(
                    SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0"), trust_policy, quorum_policy,
                    {f"observer_key_{member}": observer_keys[member].public_key() for member in ("a", "b", "c")},
                    expected_trust_policy_id="wtp_observation_network", minimum_trust_policy_version=1,
                    expected_trust_policy_hash=sha256_json(trust_policy),
                    expected_quorum_policy_id="wqp_observation_network", minimum_quorum_policy_version=1,
                    expected_quorum_policy_hash=sha256_json(quorum_policy),
                )
                source_verifier = PolicyBoundClusterReportSourceVerifier(
                    SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0"), source_policy,
                    {f"source_key_{member}": source_keys[member].public_key() for member in ("a", "b", "c")},
                    expected_policy_id="osp_observation_network", minimum_policy_version=1,
                    expected_policy_hash=sha256_json(source_policy),
                )
                verifier = IndependentObservationQuorumVerifier(
                    SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0"), quorum, source_verifier,
                )

                available_bundle = create_cluster_evidence_quorum_bundle(
                    base_report, [observations["a"]["observer_envelope"], observations["b"]["observer_envelope"]],
                    quorum_policy, source_attestations=[
                        {"observer_key_id": "observer_key_a", "source_envelope": observations["a"]["source_envelope"]},
                        {"observer_key_id": "observer_key_b", "source_envelope": observations["b"]["source_envelope"]},
                    ],
                )
                accepted = verifier.verify(base_report, available_bundle)
                self.assertEqual(["source_domain_a", "source_domain_b"], accepted["source_domains"])

                divergent_bundle = create_cluster_evidence_quorum_bundle(
                    base_report, [observations["a"]["observer_envelope"], observations["c"]["observer_envelope"]],
                    quorum_policy, source_attestations=[
                        {"observer_key_id": "observer_key_a", "source_envelope": observations["a"]["source_envelope"]},
                        {"observer_key_id": "observer_key_c", "source_envelope": observations["c"]["source_envelope"]},
                    ],
                )
                with self.assertRaises(ANOError) as divergence:
                    verifier.verify(base_report, divergent_bundle)
                self.assertEqual("EVIDENCE_SUBJECT_MISMATCH", divergence.exception.code)
            finally:
                for process, _, _, _ in sources.values():
                    self.stop(process)


if __name__ == "__main__":
    unittest.main()
