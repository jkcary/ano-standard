from __future__ import annotations

import base64
import copy
import hmac
import json
import os
import re
import subprocess
from datetime import timedelta
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import ANOError
from .hardening import sign_hmac_record
from .schema import SchemaCatalog
from .util import canonical_json, new_id, parse_timestamp, sha256_json, utc_now


def sign_ed25519_record(record: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    signed = copy.deepcopy(record)
    signed.pop("signature", None)
    signature = private_key.sign(canonical_json(signed).encode("utf-8"))
    signed["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return signed


def _verify_ed25519_record(record: dict[str, Any], public_key: Ed25519PublicKey, error_code: str) -> None:
    value = str(record.get("signature", ""))
    if not value.startswith("ed25519:"):
        raise ANOError(error_code, "Ed25519 signature is required")
    material = copy.deepcopy(record)
    material.pop("signature", None)
    try:
        signature = base64.b64decode(value.removeprefix("ed25519:"), validate=True)
        public_key.verify(signature, canonical_json(material).encode("utf-8"))
    except (ValueError, InvalidSignature) as exc:
        raise ANOError(error_code, "Ed25519 signature verification failed") from exc


class Ed25519ApprovalEvidenceVerifier:
    """Public-key verifier for production structural approval evidence."""

    def __init__(self, catalog: SchemaCatalog, trusted_keys: dict[str, Ed25519PublicKey]) -> None:
        self.catalog = catalog
        self._trusted_keys = dict(trusted_keys)

    def verify(self, evidence: dict[str, Any]) -> None:
        self.catalog.validate("structural-approval-evidence", evidence)
        key_id = str(evidence["key_id"])
        if key_id not in self._trusted_keys:
            raise ANOError("APPROVAL_ISSUER_UNTRUSTED", "approval public key is not trusted")
        _verify_ed25519_record(evidence, self._trusted_keys[key_id], "APPROVAL_SIGNATURE_INVALID")
        now = parse_timestamp(utc_now())
        issued_at, expires_at = parse_timestamp(evidence["issued_at"]), parse_timestamp(evidence["expires_at"])
        if issued_at > now or expires_at <= issued_at:
            raise ANOError("APPROVAL_TIME_INVALID", "approval validity window is inconsistent")
        if expires_at <= now:
            raise ANOError("APPROVAL_EXPIRED", "structural approval has expired")
        approvals = evidence["approvals"]
        actors = {item["approver_id"] for item in approvals}
        domains = {item["independence_domain"] for item in approvals}
        if len(actors) != len(approvals) or len(domains) < 2 or evidence["proposer_domain"] in domains:
            raise ANOError("SEPARATION_VIOLATION", "approval actors and domains must be independent")


class SignedTelemetryVerifier:
    """Authenticates remote metrics and rejects gaps, replay, reordering, and chain changes."""

    def __init__(
        self,
        catalog: SchemaCatalog,
        trusted_keys: dict[str, Ed25519PublicKey],
        *,
        maximum_future_skew_seconds: int = 60,
        cursor_store: "TelemetryCursorStore | None" = None,
    ) -> None:
        self.catalog = catalog
        self._trusted_keys = dict(trusted_keys)
        self._last: dict[tuple[str, str], tuple[int, str]] = {}
        self._future_skew = timedelta(seconds=maximum_future_skew_seconds)
        self._cursor_store = cursor_store

    def verify(self, envelope: dict[str, Any], *, deployment_id: str) -> dict[str, float]:
        self.catalog.validate("telemetry-envelope", envelope)
        if envelope["deployment_id"] != deployment_id:
            raise ANOError("TELEMETRY_BINDING_MISMATCH", "telemetry belongs to another deployment")
        key_id = str(envelope["key_id"])
        if key_id not in self._trusted_keys:
            raise ANOError("TELEMETRY_SOURCE_UNTRUSTED", "telemetry public key is not trusted")
        _verify_ed25519_record(envelope, self._trusted_keys[key_id], "TELEMETRY_SIGNATURE_INVALID")
        hash_material = copy.deepcopy(envelope)
        hash_material.pop("signature")
        supplied_hash = hash_material.pop("envelope_hash")
        if sha256_json(hash_material) != supplied_hash:
            raise ANOError("TELEMETRY_HASH_INVALID", "telemetry envelope hash is invalid")
        if parse_timestamp(envelope["observed_at"]) > parse_timestamp(utc_now()) + self._future_skew:
            raise ANOError("TELEMETRY_TIME_INVALID", "telemetry timestamp is too far in the future")
        source = str(envelope["source_id"])
        cursor_key = (deployment_id, source)
        previous = self._cursor_store.get(deployment_id, source) if self._cursor_store is not None else self._last.get(cursor_key)
        expected_sequence = 1 if previous is None else previous[0] + 1
        expected_hash = None if previous is None else previous[1]
        if envelope["sequence"] != expected_sequence or envelope["previous_hash"] != expected_hash:
            raise ANOError("TELEMETRY_REPLAY_OR_GAP", "telemetry sequence or predecessor is invalid")
        cursor = (int(envelope["sequence"]), str(envelope["envelope_hash"]))
        self._last[cursor_key] = cursor
        if self._cursor_store is not None:
            self._cursor_store.put(deployment_id, source, *cursor)
        return copy.deepcopy(envelope["metrics"])


class TelemetryCursorStore:
    """Atomically persists anti-replay cursors with keyed integrity protection."""

    def __init__(self, path: str | Path, catalog: SchemaCatalog, *, key_id: str, key: bytes) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.key_id, self._key = key_id, key
        self._version = 0
        self._cursors: dict[tuple[str, str], tuple[int, str]] = {}
        if self.path.exists():
            self._load()

    def _load(self) -> None:
        try:
            record = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ANOError("TELEMETRY_CURSOR_CORRUPT", "telemetry cursor file is unreadable") from exc
        self.catalog.validate("telemetry-cursor-set", record)
        if record["key_id"] != self.key_id:
            raise ANOError("TELEMETRY_CURSOR_KEY_MISMATCH", "telemetry cursor key identifier changed")
        expected = sign_hmac_record(record, self._key)["signature"]
        if not hmac.compare_digest(str(record["signature"]), expected):
            raise ANOError("TELEMETRY_CURSOR_CORRUPT", "telemetry cursor integrity verification failed")
        self._version = int(record["version"])
        for cursor in record["cursors"]:
            self._cursors[(cursor["deployment_id"], cursor["source_id"])] = (
                int(cursor["sequence"]), str(cursor["envelope_hash"]),
            )

    def get(self, deployment_id: str, source_id: str) -> tuple[int, str] | None:
        return self._cursors.get((deployment_id, source_id))

    def put(self, deployment_id: str, source_id: str, sequence: int, envelope_hash: str) -> None:
        self._cursors[(deployment_id, source_id)] = (sequence, envelope_hash)
        self._version += 1
        material = {
            "schema_version": "0.3.0", "version": self._version,
            "cursors": [
                {"deployment_id": deployment, "source_id": source, "sequence": value[0], "envelope_hash": value[1]}
                for (deployment, source), value in sorted(self._cursors.items())
            ],
            "updated_at": utc_now(), "key_id": self.key_id,
        }
        record = sign_hmac_record(material, self._key)
        self.catalog.validate("telemetry-cursor-set", record)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(self.path.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8", newline="\n") as handle:
            json.dump(record, handle, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(self.path)


class DeploymentProvider(Protocol):
    def stage(self, request: dict[str, Any]) -> dict[str, Any]: ...
    def rollback(self, receipt: dict[str, Any]) -> dict[str, Any]: ...


class TrafficRouter(Protocol):
    def set_fraction(self, request: dict[str, Any]) -> dict[str, Any]: ...


class ClusterValidationEvidenceVerifier:
    """Fail-closed acceptance gate for isolated-cluster validation evidence."""

    REQUIRED_SCENARIOS = frozenset({
        "cluster.deploy", "security.no_token", "security.read_only_root",
        "security.tmp_writable", "network.egress_denied", "fault.pod_recovery",
        "rollback.resources_removed",
    })

    def __init__(self, catalog: SchemaCatalog) -> None:
        self.catalog = catalog

    def verify(self, report: dict[str, Any]) -> None:
        self.catalog.validate("cluster-validation-report", report)
        scenarios = report["scenarios"]
        scenario_ids = [str(item["scenario_id"]) for item in scenarios]
        if len(scenario_ids) != len(set(scenario_ids)):
            raise ANOError("CLUSTER_EVIDENCE_DUPLICATE", "cluster scenario identifiers must be unique")
        missing = self.REQUIRED_SCENARIOS - set(scenario_ids)
        if missing:
            raise ANOError("CLUSTER_EVIDENCE_INCOMPLETE", f"missing cluster scenarios: {sorted(missing)}")
        required = [item for item in scenarios if item["scenario_id"] in self.REQUIRED_SCENARIOS]
        if any(item["status"] != "passed" for item in required):
            raise ANOError("CLUSTER_VALIDATION_FAILED", "one or more required cluster scenarios did not pass")
        if report["status"] != "passed":
            raise ANOError("CLUSTER_VALIDATION_FAILED", "cluster report did not pass")
        if not report["cleanup"]["attempted"] or not report["cleanup"]["verified"]:
            raise ANOError("CLUSTER_CLEANUP_UNVERIFIED", "isolated cluster namespace cleanup was not verified")
        if parse_timestamp(report["finished_at"]) < parse_timestamp(report["started_at"]):
            raise ANOError("CLUSTER_EVIDENCE_TIME_INVALID", "cluster validation finished before it started")


class ProductionCanaryOrchestrator:
    """Coordinates logical guards with external deployment, routing, telemetry, and compensation."""

    def __init__(
        self,
        catalog: SchemaCatalog,
        controller: Any,
        provider: DeploymentProvider,
        router: TrafficRouter,
        telemetry: SignedTelemetryVerifier,
    ) -> None:
        self.catalog = catalog
        self.controller = controller
        self.provider = provider
        self.router = router
        self.telemetry = telemetry
        self.deployment_receipt: dict[str, Any] | None = None
        self.route_receipts: list[dict[str, Any]] = []

    def stage(
        self,
        *,
        proposal_id: str,
        candidate_state: dict[str, Any],
        scope: dict[str, Any],
        guardrails: dict[str, Any],
        approval_evidence: dict[str, Any],
        artifact_ref: str,
        artifact_hash: str,
        isolation_execution_hash: str,
    ) -> dict[str, Any]:
        logical = self.controller.create(
            proposal_id=proposal_id, candidate_state=candidate_state, scope=scope,
            guardrails=guardrails, approval_evidence=approval_evidence,
        )
        try:
            receipt = self.provider.stage({
                "deployment_id": logical["deployment_id"], "artifact_ref": artifact_ref,
                "artifact_hash": artifact_hash, "isolation_execution_hash": isolation_execution_hash,
            })
            self.catalog.validate("deployment-receipt", receipt)
            if (
                receipt["deployment_id"] != logical["deployment_id"]
                or receipt["artifact_hash"] != artifact_hash
                or receipt["isolation_execution_hash"] != isolation_execution_hash
            ):
                raise ANOError("DEPLOYMENT_RECEIPT_MISMATCH", "provider receipt does not bind requested deployment")
            if receipt["status"] not in {"staged", "active"}:
                raise ANOError("DEPLOYMENT_STAGE_FAILED", "provider did not confirm a staged candidate")
            self.deployment_receipt = copy.deepcopy(receipt)
            route = self.router.set_fraction({
                "deployment_id": logical["deployment_id"], "candidate_fraction": scope["traffic_fraction"],
                "scope_hash": sha256_json(scope),
            })
            self.catalog.validate("traffic-route", route)
            if (
                route["deployment_id"] != logical["deployment_id"] or route["status"] != "applied"
                or route["candidate_fraction"] > scope["traffic_fraction"]
                or route["scope_hash"] != sha256_json(scope)
            ):
                raise ANOError("TRAFFIC_SCOPE_VIOLATION", "router exceeded approved canary scope")
            self.route_receipts.append(copy.deepcopy(route))
            return copy.deepcopy(logical)
        except Exception:
            self.controller.fail_safe_rollback("CONTROL_PLANE_STAGE_FAILURE")
            if self.deployment_receipt is not None:
                self._compensate()
            raise

    def ingest(self, envelope: dict[str, Any], *, observation_window_complete: bool = False) -> str:
        snapshot = self.controller.snapshot()
        deployment_id = snapshot["deployment"]["deployment_id"]
        metrics = self.telemetry.verify(envelope, deployment_id=deployment_id)
        status = self.controller.observe(metrics, observation_window_complete=observation_window_complete)
        if status == "rolled_back":
            self._compensate()
        # Logical promotion means the candidate passed the observation window. External
        # traffic remains at the approved canary fraction until a separately authorized
        # full-rollout protocol is supplied by the production implementation.
        return status

    def _compensate(self) -> None:
        assert self.deployment_receipt is not None
        deployment_id = self.deployment_receipt["deployment_id"]
        scope_hash = self.controller.snapshot()["deployment"].get("scope")
        route: dict[str, Any] | None = None
        rollback: dict[str, Any] | None = None
        errors: list[Exception] = []
        try:
            route = self.router.set_fraction({
                "deployment_id": deployment_id, "candidate_fraction": 0,
                "scope_hash": sha256_json(scope_hash),
            })
            self.catalog.validate("traffic-route", route)
        except Exception as exc:
            errors.append(exc)
        try:
            rollback = self.provider.rollback(self.deployment_receipt)
            self.catalog.validate("deployment-receipt", rollback)
        except Exception as exc:
            errors.append(exc)
        if (
            errors or route is None or rollback is None
            or route["deployment_id"] != deployment_id or route["candidate_fraction"] != 0
            or route["status"] not in {"applied", "rolled_back"}
            or rollback["status"] != "rolled_back" or rollback["deployment_id"] != deployment_id
        ):
            raise ANOError("CONTROL_PLANE_COMPENSATION_FAILED", "external rollback could not be verified")
        self.route_receipts.append(copy.deepcopy(route))
        self.deployment_receipt = copy.deepcopy(rollback)


class KubectlDeploymentProvider:
    """Explicit-context Kubernetes adapter; dry-run is the safe default."""

    _IMAGE = re.compile(r"^[a-zA-Z0-9._:/-]+@sha256:[a-f0-9]{64}$")

    def __init__(
        self,
        *,
        context: str,
        namespace: str,
        provider_id: str = "kubernetes_provider_001",
        kubectl: str = "kubectl",
        dry_run: bool = True,
        command: list[str] | None = None,
    ) -> None:
        if not context or not namespace:
            raise ValueError("explicit Kubernetes context and namespace are required")
        self.context, self.namespace = context, namespace
        self.provider_id, self.kubectl, self.dry_run = provider_id, kubectl, dry_run
        self.command = list(command) if command is not None else None
        self._generation = 0

    def build_manifest(self, request: dict[str, Any]) -> dict[str, Any]:
        image = str(request["artifact_ref"])
        if not self._IMAGE.fullmatch(image) or image.rsplit("@", 1)[1] != request["artifact_hash"]:
            raise ANOError("KUBERNETES_IMAGE_UNPINNED", "candidate image must match the approved digest")
        suffix = re.sub(r"[^a-z0-9-]", "-", str(request["deployment_id"]).lower().replace("_", "-")).strip("-")[-48:]
        name = "ano-" + suffix
        labels = {"app.kubernetes.io/name": name, "ano.dev/deployment-id": name}
        deployment = {
            "apiVersion": "apps/v1", "kind": "Deployment", "metadata": {"name": name, "namespace": self.namespace, "labels": labels},
            "spec": {"replicas": 1, "selector": {"matchLabels": labels}, "template": {
                "metadata": {"labels": labels}, "spec": {"automountServiceAccountToken": False,
                    "securityContext": {"runAsNonRoot": True, "runAsUser": 65534, "runAsGroup": 65534, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "candidate", "image": image,
                        "securityContext": {"allowPrivilegeEscalation": False, "readOnlyRootFilesystem": True, "capabilities": {"drop": ["ALL"]}},
                        "resources": {"requests": {"cpu": "100m", "memory": "128Mi"}, "limits": {"cpu": "500m", "memory": "256Mi"}},
                        "volumeMounts": [{"name": "tmp", "mountPath": "/tmp"}],
                        **({"command": self.command} if self.command is not None else {})}],
                    "volumes": [{"name": "tmp", "emptyDir": {"sizeLimit": "64Mi"}}],
                }},
            },
        }
        network_policy = {
            "apiVersion": "networking.k8s.io/v1", "kind": "NetworkPolicy",
            "metadata": {"name": name + "-deny-all", "namespace": self.namespace},
            "spec": {"podSelector": {"matchLabels": labels}, "policyTypes": ["Ingress", "Egress"], "ingress": [], "egress": []},
        }
        return {"apiVersion": "v1", "kind": "List", "items": [deployment, network_policy]}

    def stage(self, request: dict[str, Any]) -> dict[str, Any]:
        manifest = self.build_manifest(request)
        if not self.dry_run:
            command = [self.kubectl, "--context", self.context, "--namespace", self.namespace, "apply", "--server-side", "--field-manager", "ano-control-plane", "-f", "-"]
            completed = subprocess.run(command, input=json.dumps(manifest), text=True, capture_output=True, timeout=30, check=False)
            if completed.returncode != 0:
                raise ANOError("KUBERNETES_APPLY_FAILED", completed.stderr[-1024:] or "kubectl apply failed")
        self._generation += 1
        name = manifest["items"][0]["metadata"]["name"]
        return {
            "receipt_id": new_id("dep"), "schema_version": "0.3.0", "deployment_id": request["deployment_id"],
            "provider_id": self.provider_id, "artifact_hash": request["artifact_hash"],
            "isolation_execution_hash": request["isolation_execution_hash"],
            "external_ref": f"kubernetes://{self.context}/{self.namespace}/{name}",
            "generation": self._generation, "created_at": utc_now(), "status": "staged",
        }

    def rollback(self, receipt: dict[str, Any]) -> dict[str, Any]:
        if not self.dry_run:
            name = str(receipt["external_ref"]).rstrip("/").rsplit("/", 1)[-1]
            command = [
                self.kubectl, "--context", self.context, "--namespace", self.namespace,
                "delete", f"deployment/{name}", f"networkpolicy/{name}-deny-all",
                "--ignore-not-found=true", "--wait=true",
            ]
            completed = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
            if completed.returncode != 0:
                raise ANOError("KUBERNETES_ROLLBACK_FAILED", completed.stderr[-1024:] or "kubectl delete failed")
        rolled_back = copy.deepcopy(receipt)
        self._generation += 1
        rolled_back["receipt_id"] = new_id("dep")
        rolled_back["generation"] = self._generation
        rolled_back["created_at"] = utc_now()
        rolled_back["status"] = "rolled_back"
        return rolled_back
