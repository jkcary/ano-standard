from __future__ import annotations

import datetime
import ipaddress
import json
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from ano_runtime import sha256_json, witness_public_key_fingerprint
from tests.support import STANDARD_ROOT, conformance, load_example


class MutualTlsWitnessConformanceTests(unittest.TestCase):
    service_tool = STANDARD_ROOT / "tools" / "run_witness_service.py"
    client_tool = STANDARD_ROOT / "tools" / "request_cluster_witness.py"

    @staticmethod
    def create_ca(common_name: str) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
        now = datetime.datetime.now(datetime.timezone.utc)
        certificate = (
            x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=2))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=True,
                encipher_only=False, decipher_only=False,
            ), critical=True)
            .sign(key, hashes.SHA256())
        )
        return key, certificate

    @staticmethod
    def create_leaf(
        ca_key: rsa.RSAPrivateKey, ca_cert: x509.Certificate, common_name: str,
        usage: ExtendedKeyUsageOID, *, server: bool = False,
    ) -> tuple[rsa.RSAPrivateKey, x509.Certificate]:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.datetime.now(datetime.timezone.utc)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .issuer_name(ca_cert.subject).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(hours=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.ExtendedKeyUsage([usage]), critical=False)
            .add_extension(x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=True,
                data_encipherment=False, key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False,
            ), critical=True)
        )
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]), critical=False)
        return key, builder.sign(ca_key, hashes.SHA256())

    @staticmethod
    def write_key(path: Path, key: object) -> None:
        path.write_bytes(key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption(),
        ))

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

    @conformance("S-MTLS-001")
    def test_service_requires_trusted_client_certificate_and_client_verifies_server(self) -> None:
        with tempfile.TemporaryDirectory() as directory_name:
            directory = Path(directory_name)
            ca_key, ca_cert = self.create_ca("ANO test CA")
            server_key, server_cert = self.create_leaf(
                ca_key, ca_cert, "ANO witness server", ExtendedKeyUsageOID.SERVER_AUTH, server=True,
            )
            client_key, client_cert = self.create_leaf(
                ca_key, ca_cert, "ANO archive client", ExtendedKeyUsageOID.CLIENT_AUTH,
            )
            rogue_ca_key, rogue_ca_cert = self.create_ca("rogue CA")
            rogue_key, rogue_cert = self.create_leaf(
                rogue_ca_key, rogue_ca_cert, "rogue client", ExtendedKeyUsageOID.CLIENT_AUTH,
            )
            paths = {
                "ca": directory / "ca.pem", "server_key": directory / "server-key.pem",
                "server_cert": directory / "server.pem", "client_key": directory / "client-key.pem",
                "client_cert": directory / "client.pem", "rogue_key": directory / "rogue-key.pem",
                "rogue_cert": directory / "rogue.pem", "witness_key": directory / "witness-key.pem",
                "witness_public": directory / "witness-public.pem", "token": directory / "token.txt",
                "state": directory / "state.json", "ready": directory / "ready.json",
                "report": directory / "report.json", "output": directory / "envelope.json",
                "policy": directory / "policy.json", "rogue_ca": directory / "rogue-ca.pem",
            }
            paths["ca"].write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
            paths["server_cert"].write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
            paths["client_cert"].write_bytes(client_cert.public_bytes(serialization.Encoding.PEM))
            paths["rogue_cert"].write_bytes(rogue_cert.public_bytes(serialization.Encoding.PEM))
            paths["rogue_ca"].write_bytes(rogue_ca_cert.public_bytes(serialization.Encoding.PEM))
            self.write_key(paths["server_key"], server_key)
            self.write_key(paths["client_key"], client_key)
            self.write_key(paths["rogue_key"], rogue_key)
            witness_key = ed25519.Ed25519PrivateKey.generate()
            self.write_key(paths["witness_key"], witness_key)
            paths["witness_public"].write_bytes(witness_key.public_key().public_bytes(
                serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo,
            ))
            paths["token"].write_text("alpha11-mtls-bearer-token-000001\n", encoding="utf-8")
            paths["report"].write_text(json.dumps(load_example("cluster-validation-report")), encoding="utf-8")
            policy = {
                "policy_id": "wtp_mtls_001", "schema_version": "0.3.0", "policy_version": 1,
                "issued_at": "2026-08-27T17:00:00Z", "keys": [{
                    "key_id": "witness_ed25519_001", "algorithm": "Ed25519", "witness_domain": "independent_evidence_domain",
                    "public_key_sha256": witness_public_key_fingerprint(witness_key.public_key()),
                    "status": "active", "valid_from": "2026-08-27T17:00:00Z",
                    "valid_until": "2027-08-27T17:00:00Z", "revoked_at": None, "revocation_mode": "none",
                }],
            }
            paths["policy"].write_text(json.dumps(policy), encoding="utf-8")

            process = subprocess.Popen([
                sys.executable, str(self.service_tool), "--private-key", str(paths["witness_key"]),
                "--token-file", str(paths["token"]), "--state", str(paths["state"]),
                "--key-id", "witness_ed25519_001", "--runner-domain", "cluster_lab_domain",
                "--witness-domain", "independent_evidence_domain", "--port", "0",
                "--tls-cert", str(paths["server_cert"]), "--tls-key", str(paths["server_key"]),
                "--client-ca", str(paths["ca"]), "--ready-file", str(paths["ready"]),
            ], cwd=STANDARD_ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline and not paths["ready"].exists() and process.poll() is None:
                    time.sleep(0.05)
                if not paths["ready"].exists():
                    stdout, stderr = process.communicate(timeout=2)
                    self.fail(f"mTLS witness did not start: {stdout}\n{stderr}")
                ready = json.loads(paths["ready"].read_text(encoding="utf-8"))
                self.assertEqual("mtls", ready["transport"])
                url = ready["url"]

                no_client = ssl.create_default_context(cafile=str(paths["ca"]))
                with self.assertRaises((urllib.error.URLError, ssl.SSLError, ConnectionResetError)):
                    urllib.request.urlopen(url + "/healthz", timeout=5, context=no_client)

                rogue = ssl.create_default_context(cafile=str(paths["ca"]))
                rogue.load_cert_chain(str(paths["rogue_cert"]), str(paths["rogue_key"]))
                with self.assertRaises((urllib.error.URLError, ssl.SSLError, ConnectionResetError)):
                    urllib.request.urlopen(url + "/healthz", timeout=5, context=rogue)

                untrusted_server = subprocess.run([
                    sys.executable, str(self.client_tool), "--url", url,
                    "--token-file", str(paths["token"]), "--report", str(paths["report"]),
                    "--public-key", str(paths["witness_public"]), "--key-id", "witness_ed25519_001",
                    "--witness-domain", "independent_evidence_domain", "--expected-sequence", "1",
                    "--ca-cert", str(paths["rogue_ca"]), "--client-cert", str(paths["client_cert"]),
                    "--client-key", str(paths["client_key"]), "--output", str(paths["output"]),
                ], cwd=STANDARD_ROOT, text=True, capture_output=True, timeout=20, check=False)
                self.assertNotEqual(0, untrusted_server.returncode)

                result = subprocess.run([
                    sys.executable, str(self.client_tool), "--url", url,
                    "--token-file", str(paths["token"]), "--report", str(paths["report"]),
                    "--public-key", str(paths["witness_public"]), "--key-id", "witness_ed25519_001",
                    "--witness-domain", "independent_evidence_domain", "--expected-sequence", "1",
                    "--ca-cert", str(paths["ca"]), "--client-cert", str(paths["client_cert"]),
                    "--client-key", str(paths["client_key"]), "--output", str(paths["output"]),
                    "--trust-policy", str(paths["policy"]), "--expected-policy-id", "wtp_mtls_001",
                    "--minimum-policy-version", "1", "--expected-policy-hash", sha256_json(policy),
                ], cwd=STANDARD_ROOT, text=True, capture_output=True, timeout=20, check=False)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertTrue(paths["output"].exists())
            finally:
                self.stop(process)


if __name__ == "__main__":
    unittest.main()
