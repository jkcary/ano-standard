from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ano_runtime import (
    ANOError, IndependentWitnessQuorumVerifier, SchemaCatalog,
    create_cluster_evidence_quorum_bundle, sha256_json,
)

from tests.support import STANDARD_ROOT, conformance, load_example
from tests.test_quorum_evidence import timestamp, trust_entry


class WitnessQuorumNetworkConformanceTests(unittest.TestCase):
    service_tool = STANDARD_ROOT / "tools" / "run_witness_service.py"

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

    def start(
        self, directory: Path, member: str, key: Ed25519PrivateKey,
    ) -> tuple[subprocess.Popen[str], str, str]:
        key_path, token_path = directory / f"{member}.pem", directory / f"{member}.token"
        state_path, ready_path = directory / f"{member}.state.json", directory / f"{member}.ready.json"
        key_path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))
        token = f"alpha12-{member}-bearer-token-000001"
        token_path.write_text(token + "\n", encoding="utf-8")
        process = subprocess.Popen([
            sys.executable, str(self.service_tool), "--private-key", str(key_path),
            "--token-file", str(token_path), "--state", str(state_path),
            "--key-id", f"key_{member}", "--runner-domain", "cluster_lab_domain",
            "--witness-domain", f"evidence_domain_{member}", "--port", "0",
            "--ready-file", str(ready_path),
        ], cwd=STANDARD_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if ready_path.exists():
                return process, json.loads(ready_path.read_text(encoding="utf-8"))["url"], token
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(f"witness {member} failed to start: {stdout}\n{stderr}")
            time.sleep(0.05)
        self.stop(process)
        self.fail(f"witness {member} startup timed out")

    @staticmethod
    def issue(url: str, token: str, report: dict) -> dict:
        body = json.dumps({"report": report}, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(
            url + "/v1/witness", data=body, method="POST",
            headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))["envelope"]

    @conformance("S-QNET-001")
    def test_two_of_three_remains_available_when_one_independent_service_is_down(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            keys = {member: Ed25519PrivateKey.generate() for member in ("a", "b", "c")}
            services: dict[str, tuple[subprocess.Popen[str], str, str]] = {}
            try:
                for member in keys:
                    services[member] = self.start(directory, member, keys[member])
                failed_url = services["c"][1]
                self.stop(services["c"][0])
                with self.assertRaises((urllib.error.URLError, ConnectionError)):
                    urllib.request.urlopen(failed_url + "/healthz", timeout=2)

                report = load_example("cluster-validation-report")
                envelope_a = self.issue(services["a"][1], services["a"][2], report)
                envelope_b = self.issue(services["b"][1], services["b"][2], report)
                now = datetime.now(timezone.utc)
                trust_policy = {
                    "policy_id": "wtp_network_001", "schema_version": "0.3.0", "policy_version": 1,
                    "issued_at": timestamp(now), "keys": [
                        trust_entry(f"key_{member}", key, f"evidence_domain_{member}", now=now)
                        for member, key in keys.items()
                    ],
                }
                quorum_policy = {
                    "policy_id": "wqp_network_001", "schema_version": "0.3.0", "policy_version": 1,
                    "issued_at": timestamp(now), "threshold": 2, "required_member_ids": [],
                    "maximum_witness_spread_seconds": 300, "maximum_bundle_delay_seconds": 600,
                    "members": [
                        {"member_id": f"member_{member}", "witness_domain": f"evidence_domain_{member}", "key_ids": [f"key_{member}"]}
                        for member in keys
                    ],
                }
                verifier = IndependentWitnessQuorumVerifier(
                    SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0"), trust_policy, quorum_policy,
                    {f"key_{member}": key.public_key() for member, key in keys.items()},
                    expected_trust_policy_id="wtp_network_001", minimum_trust_policy_version=1,
                    expected_trust_policy_hash=sha256_json(trust_policy),
                    expected_quorum_policy_id="wqp_network_001", minimum_quorum_policy_version=1,
                    expected_quorum_policy_hash=sha256_json(quorum_policy),
                )
                available_bundle = create_cluster_evidence_quorum_bundle(report, [envelope_a, envelope_b], quorum_policy)
                accepted = verifier.verify(report, available_bundle)
                self.assertEqual(["member_a", "member_b"], accepted["member_ids"])
                unavailable_bundle = create_cluster_evidence_quorum_bundle(report, [envelope_a], quorum_policy)
                with self.assertRaises(ANOError) as unavailable:
                    verifier.verify(report, unavailable_bundle)
                self.assertEqual("WITNESS_QUORUM_NOT_MET", unavailable.exception.code)
            finally:
                for process, _, _ in services.values():
                    self.stop(process)


if __name__ == "__main__":
    unittest.main()
