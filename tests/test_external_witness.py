from __future__ import annotations

import copy
import base64
import json
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ano_runtime import (
    ANOError, DurableWitnessIssuer, SchemaCatalog, WitnessedEvidenceLedger,
)

from tests.support import STANDARD_ROOT, conformance, load_example


class ExternalWitnessServiceConformanceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = SchemaCatalog(STANDARD_ROOT / "schemas" / "v0.3.0")
        cls.service_tool = STANDARD_ROOT / "tools" / "run_witness_service.py"
        cls.client_tool = STANDARD_ROOT / "tools" / "request_cluster_witness.py"

    def prepare(self, directory: Path) -> dict[str, Path]:
        private = Ed25519PrivateKey.generate()
        private_path, public_path = directory / "private.pem", directory / "public.pem"
        private_path.write_bytes(private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        public_path.write_bytes(private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
        ))
        token_path = directory / "token.txt"
        token_path.write_text("alpha10-test-bearer-token-000001\n", encoding="utf-8")
        report_path = directory / "report.json"
        report_path.write_text(json.dumps(load_example("cluster-validation-report")), encoding="utf-8")
        return {
            "private": private_path, "public": public_path, "token": token_path,
            "report": report_path, "state": directory / "state.json",
            "ready": directory / "ready.json", "output": directory / "envelope.json",
        }

    def start_service(self, paths: dict[str, Path]) -> tuple[subprocess.Popen[str], str]:
        paths["ready"].unlink(missing_ok=True)
        process = subprocess.Popen(
            [
                sys.executable, str(self.service_tool), "--private-key", str(paths["private"]),
                "--token-file", str(paths["token"]), "--state", str(paths["state"]),
                "--key-id", "witness_ed25519_001", "--runner-domain", "cluster_lab_domain",
                "--witness-domain", "independent_evidence_domain", "--port", "0",
                "--ready-file", str(paths["ready"]),
            ],
            cwd=STANDARD_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            if paths["ready"].exists():
                return process, json.loads(paths["ready"].read_text(encoding="utf-8"))["url"]
            if process.poll() is not None:
                stdout, stderr = process.communicate()
                self.fail(f"witness service exited during startup: {stdout}\n{stderr}")
            time.sleep(0.05)
        self.stop_service(process)
        self.fail("witness service did not become ready")

    @staticmethod
    def stop_service(process: subprocess.Popen[str]) -> None:
        if process.poll() is None:
            process.terminate()
            try:
                process.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)
        else:
            process.communicate()

    def request(self, paths: dict[str, Path], url: str, *, sequence: int, previous: str | None = None) -> subprocess.CompletedProcess[str]:
        command = [
            sys.executable, str(self.client_tool), "--url", url,
            "--token-file", str(paths["token"]), "--report", str(paths["report"]),
            "--public-key", str(paths["public"]), "--key-id", "witness_ed25519_001",
            "--witness-domain", "independent_evidence_domain", "--expected-sequence", str(sequence),
            "--output", str(paths["output"]),
        ]
        if previous is not None:
            command.extend(["--expected-previous-hash", previous])
        return subprocess.run(command, cwd=STANDARD_ROOT, text=True, capture_output=True, timeout=20, check=False)

    @conformance("S-XWIT-001")
    def test_external_process_requires_auth_and_idempotently_returns_verified_envelope(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            paths = self.prepare(Path(directory_name))
            process, url = self.start_service(paths)
            try:
                body = json.dumps({"report": load_example("cluster-validation-report")}).encode("utf-8")
                unauthorized = urllib.request.Request(
                    url + "/v1/witness", data=body, method="POST",
                    headers={"Authorization": "Bearer wrong-token", "Content-Type": "application/json"},
                )
                with self.assertRaises(urllib.error.HTTPError) as denied:
                    urllib.request.urlopen(unauthorized, timeout=5)
                self.assertEqual(401, denied.exception.code)
                denied.exception.close()

                first = self.request(paths, url, sequence=1)
                self.assertEqual(0, first.returncode, first.stderr)
                original = paths["output"].read_bytes()
                retry = self.request(paths, url, sequence=1)
                self.assertEqual(0, retry.returncode, retry.stderr)
                self.assertEqual(original, paths["output"].read_bytes())
                state = json.loads(paths["state"].read_text(encoding="utf-8"))
                self.assertEqual(1, state["sequence"])
            finally:
                self.stop_service(process)

    @conformance("S-XREC-001")
    def test_external_witness_restart_continues_chain_and_rejects_corrupt_state(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            paths = self.prepare(Path(directory_name))
            first_process, first_url = self.start_service(paths)
            try:
                first = self.request(paths, first_url, sequence=1)
                self.assertEqual(0, first.returncode, first.stderr)
            finally:
                self.stop_service(first_process)
            first_envelope = json.loads(paths["output"].read_text(encoding="utf-8"))
            previous = WitnessedEvidenceLedger.envelope_hash(first_envelope)

            second_report = copy.deepcopy(load_example("cluster-validation-report"))
            second_report["run_id"] = "lab_demo_002"
            second_report["namespace"] = "ano-alpha8-b2c3d4e5"
            paths["report"].write_text(json.dumps(second_report), encoding="utf-8")
            second_process, second_url = self.start_service(paths)
            try:
                second = self.request(paths, second_url, sequence=2, previous=previous)
                self.assertEqual(0, second.returncode, second.stderr)
                paths["report"].write_text(json.dumps(load_example("cluster-validation-report")), encoding="utf-8")
                historical_retry = self.request(paths, second_url, sequence=1)
                self.assertEqual(0, historical_retry.returncode, historical_retry.stderr)
            finally:
                self.stop_service(second_process)
            state = json.loads(paths["state"].read_text(encoding="utf-8"))
            self.assertEqual(2, state["sequence"])
            self.assertEqual(previous, json.loads(
                base64.b64decode(state["last_envelope"]["payload"])
            )["previous_envelope_hash"])

            state["sequence"] = 99
            paths["state"].write_text(json.dumps(state), encoding="utf-8")
            loaded = serialization.load_pem_private_key(paths["private"].read_bytes(), password=None)
            self.assertIsInstance(loaded, Ed25519PrivateKey)
            with self.assertRaises(ANOError) as corrupt:
                DurableWitnessIssuer(
                    paths["state"], self.catalog, loaded,
                    key_id="witness_ed25519_001", runner_domain="cluster_lab_domain",
                    witness_domain="independent_evidence_domain",
                )
            self.assertEqual("WITNESS_STATE_CORRUPT", corrupt.exception.code)


if __name__ == "__main__":
    unittest.main()
