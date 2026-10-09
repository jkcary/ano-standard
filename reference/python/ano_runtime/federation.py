from __future__ import annotations

import base64
import copy
import json
import math
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import ANOError
from .evolution import CapabilityPackageVerifier
from .schema import SchemaCatalog
from .util import canonical_json, new_id, parse_timestamp, sha256_json


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _sign(material: dict[str, Any], private_key: Ed25519PrivateKey) -> str:
    return base64.b64encode(private_key.sign(canonical_json(material).encode())).decode()


def _verify(record: dict[str, Any], public_key: Ed25519PublicKey, code: str) -> None:
    material = copy.deepcopy(record)
    signature = material.pop("signature")
    try:
        public_key.verify(base64.b64decode(signature, validate=True), canonical_json(material).encode())
    except (ValueError, InvalidSignature) as exc:
        raise ANOError(code, "signed federation record verification failed") from exc


class FederationBundleSigner:
    def __init__(
        self, catalog: SchemaCatalog, federation_id: str, issuer: str, key_id: str,
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.catalog, self.federation_id, self.issuer, self.key_id = catalog, federation_id, issuer, key_id
        self.private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def create(
        self, epoch: int, policy: dict[str, Any], packages: list[dict[str, Any]], *,
        previous_bundle_hash: str | None, now: datetime | None = None,
    ) -> dict[str, Any]:
        self.catalog.validate("federation-policy", policy)
        if epoch < 1 or (epoch == 1) != (previous_bundle_hash is None):
            raise ANOError("FEDERATION_EPOCH_INVALID", "genesis and non-genesis bundle linkage is invalid")
        package_hashes = [str(item["package_hash"]) for item in packages]
        if len(package_hashes) != len(set(package_hashes)):
            raise ANOError("FEDERATION_PACKAGE_DUPLICATE", "bundle contains a duplicate package")
        view_hash = sha256_json({"policy": policy, "package_hashes": sorted(package_hashes)})
        material = {
            "bundle_id": new_id("fdb"), "schema_version": "0.5.0", "federation_id": self.federation_id,
            "epoch": epoch, "previous_bundle_hash": previous_bundle_hash, "policy": copy.deepcopy(policy),
            "packages": copy.deepcopy(packages), "view_hash": view_hash,
            "issuer": self.issuer, "key_id": self.key_id,
            "issued_at": _stamp(now or datetime.now(timezone.utc)),
        }
        signed = {**material, "bundle_hash": sha256_json(material)}
        result = {**signed, "signature": _sign(signed, self.private_key)}
        self.catalog.validate("federation-release-bundle", result)
        return result


class FederationBundleVerifier:
    def __init__(
        self, catalog: SchemaCatalog, capability_verifier: CapabilityPackageVerifier, *,
        federation_id: str, trusted_issuers: set[str], trusted_keys: dict[str, Ed25519PublicKey],
    ) -> None:
        self.catalog, self.capability_verifier = catalog, capability_verifier
        self.federation_id, self.trusted_issuers, self.trusted_keys = federation_id, set(trusted_issuers), dict(trusted_keys)

    def verify(self, bundle: dict[str, Any]) -> None:
        self.catalog.validate("federation-release-bundle", bundle)
        if bundle["federation_id"] != self.federation_id or bundle["issuer"] not in self.trusted_issuers:
            raise ANOError("FEDERATION_TRUST_MISMATCH", "bundle federation or issuer is not trusted")
        key = self.trusted_keys.get(bundle["key_id"])
        if key is None:
            raise ANOError("FEDERATION_KEY_UNTRUSTED", "bundle signing key is not trusted")
        _verify(bundle, key, "FEDERATION_SIGNATURE_INVALID")
        signed = copy.deepcopy(bundle)
        signed.pop("signature")
        bundle_hash = signed.pop("bundle_hash")
        if bundle_hash != sha256_json(signed):
            raise ANOError("FEDERATION_BUNDLE_HASH_INVALID", "bundle hash does not bind its content")
        self.catalog.validate("federation-policy", bundle["policy"])
        policy = bundle["policy"]
        if policy["minimum_view_quorum"] > len(policy["allowed_node_ids"]) or policy["slo_minimum_nodes"] > len(policy["allowed_node_ids"]):
            raise ANOError("FEDERATION_POLICY_INVALID", "quorum requirements exceed allowed federation nodes")
        if any(target["minimum_nodes"] > len(policy["allowed_node_ids"]) for target in policy["slo_targets"].values()):
            raise ANOError("FEDERATION_POLICY_INVALID", "an SLO target quorum exceeds allowed federation nodes")
        global_dimensions = set(policy["global_budget_limits"])
        if any(not set(limits).issubset(global_dimensions) for limits in policy["tenant_budget_limits"].values()):
            raise ANOError("FEDERATION_POLICY_INVALID", "tenant budget uses a dimension absent from the global policy")
        components: set[str] = set()
        for package in bundle["packages"]:
            self.capability_verifier.verify(package)
            if package["component_id"] in components:
                raise ANOError("FEDERATION_COMPONENT_DUPLICATE", "view contains multiple active packages for one component")
            components.add(package["component_id"])
        expected_view = sha256_json({
            "policy": bundle["policy"],
            "package_hashes": sorted(str(item["package_hash"]) for item in bundle["packages"]),
        })
        if bundle["view_hash"] != expected_view:
            raise ANOError("FEDERATION_VIEW_HASH_INVALID", "view hash does not bind policy and packages")


class SqliteFederatedNode:
    """A node accepts only a continuous, signed federation history and signs its local view."""

    def __init__(
        self, path: str | Path, catalog: SchemaCatalog, node_id: str,
        verifier: FederationBundleVerifier, node_key_id: str,
        node_private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.path, self.catalog, self.node_id, self.verifier = Path(path), catalog, node_id, verifier
        self.node_key_id, self.node_private_key = node_key_id, node_private_key or Ed25519PrivateKey.generate()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS federation_views (
                    epoch INTEGER PRIMARY KEY, bundle_hash TEXT UNIQUE NOT NULL,
                    view_hash TEXT NOT NULL, bundle_json TEXT NOT NULL, applied_at TEXT NOT NULL);
            """)
            connection.commit()
        finally:
            connection.close()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.node_private_key.public_key()

    def current(self) -> dict[str, Any] | None:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        try:
            row = connection.execute("SELECT * FROM federation_views ORDER BY epoch DESC LIMIT 1").fetchone()
            return None if row is None else json.loads(row["bundle_json"])
        finally:
            connection.close()

    def apply(self, bundle: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        self.verifier.verify(bundle)
        if self.node_id not in bundle["policy"]["allowed_node_ids"]:
            raise ANOError("FEDERATION_NODE_DENIED", "node is outside the signed federation policy")
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT bundle_hash,bundle_json FROM federation_views WHERE epoch=?", (bundle["epoch"],)).fetchone()
            if existing is not None:
                if existing["bundle_hash"] != bundle["bundle_hash"]:
                    raise ANOError("FEDERATION_EQUIVOCATION", "different bundles claim the same federation epoch")
                connection.commit()
                return json.loads(existing["bundle_json"])
            head = connection.execute("SELECT epoch,bundle_hash FROM federation_views ORDER BY epoch DESC LIMIT 1").fetchone()
            expected_epoch = 1 if head is None else int(head["epoch"]) + 1
            expected_previous = None if head is None else str(head["bundle_hash"])
            if bundle["epoch"] != expected_epoch or bundle["previous_bundle_hash"] != expected_previous:
                raise ANOError("FEDERATION_HISTORY_GAP", "bundle does not continuously extend the local federation history")
            if head is not None:
                previous_row = connection.execute("SELECT bundle_json FROM federation_views WHERE epoch=?", (head["epoch"],)).fetchone()
                previous_bundle = json.loads(previous_row["bundle_json"])
                old_policy, new_policy = previous_bundle["policy"], bundle["policy"]
                if new_policy["version"] < old_policy["version"] or (
                    new_policy["version"] == old_policy["version"] and sha256_json(new_policy) != sha256_json(old_policy)
                ):
                    raise ANOError("FEDERATION_POLICY_ROLLBACK", "policy version regressed or changed without advancing")
                previous_packages = {item["component_id"]: item for item in previous_bundle["packages"]}
                for package in bundle["packages"]:
                    old = previous_packages.get(package["component_id"])
                    if old is not None and (
                        package["generation"] < old["generation"]
                        or (package["generation"] == old["generation"] and package["package_hash"] != old["package_hash"])
                    ):
                        raise ANOError("FEDERATION_PACKAGE_ROLLBACK", "component generation regressed or equivocated")
            connection.execute(
                "INSERT INTO federation_views VALUES(?,?,?,?,?)",
                (bundle["epoch"], bundle["bundle_hash"], bundle["view_hash"], canonical_json(bundle), _stamp(now or datetime.now(timezone.utc))),
            )
            connection.commit()
            return copy.deepcopy(bundle)
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def catch_up(self, bundles: list[dict[str, Any]]) -> dict[str, Any] | None:
        for bundle in bundles:
            self.apply(bundle)
        return self.current()

    def checkpoint(self, *, now: datetime | None = None) -> dict[str, Any]:
        current = self.current()
        if current is None:
            raise ANOError("FEDERATION_VIEW_EMPTY", "node has no accepted federation view")
        material = {
            "checkpoint_id": new_id("fvc"), "schema_version": "0.5.0",
            "federation_id": current["federation_id"], "node_id": self.node_id,
            "epoch": current["epoch"], "bundle_hash": current["bundle_hash"], "view_hash": current["view_hash"],
            "key_id": self.node_key_id, "observed_at": _stamp(now or datetime.now(timezone.utc)),
        }
        result = {**material, "signature": _sign(material, self.node_private_key)}
        self.catalog.validate("federation-view-checkpoint", result)
        return result


class FederationViewReconciler:
    def __init__(
        self, catalog: SchemaCatalog, federation_id: str,
        trusted_nodes: dict[str, tuple[str, str, Ed25519PublicKey]], *, quorum: int,
    ) -> None:
        self.catalog, self.federation_id, self.trusted_nodes, self.quorum = catalog, federation_id, dict(trusted_nodes), quorum

    def reconcile(self, checkpoints: list[dict[str, Any]], *, minimum_epoch: int) -> dict[str, Any]:
        if minimum_epoch < 1:
            raise ANOError("FEDERATION_EPOCH_ANCHOR_INVALID", "minimum trusted epoch must be positive")
        nodes, domains, views = set(), set(), set()
        for checkpoint in checkpoints:
            self.catalog.validate("federation-view-checkpoint", checkpoint)
            trust = self.trusted_nodes.get(checkpoint["node_id"])
            if trust is None or trust[1] != checkpoint["key_id"] or checkpoint["federation_id"] != self.federation_id:
                raise ANOError("FEDERATION_CHECKPOINT_UNTRUSTED", "checkpoint node, key, or federation is not trusted")
            _verify(checkpoint, trust[2], "FEDERATION_CHECKPOINT_SIGNATURE_INVALID")
            if checkpoint["node_id"] in nodes or trust[0] in domains:
                raise ANOError("FEDERATION_QUORUM_NOT_INDEPENDENT", "checkpoint quorum repeats a node or failure domain")
            nodes.add(checkpoint["node_id"]); domains.add(trust[0])
            views.add((checkpoint["epoch"], checkpoint["bundle_hash"], checkpoint["view_hash"]))
        if len(nodes) < self.quorum:
            raise ANOError("FEDERATION_QUORUM_MISSING", "not enough independent node checkpoints")
        if len(views) != 1:
            raise ANOError("FEDERATION_VIEW_DIVERGED", "trusted nodes do not report one consistent view")
        epoch, bundle_hash, view_hash = next(iter(views))
        if epoch < minimum_epoch:
            raise ANOError("FEDERATION_CHECKPOINT_ROLLBACK", "checkpoint quorum is older than the minimum trusted epoch")
        return {"epoch": epoch, "bundle_hash": bundle_hash, "view_hash": view_hash, "node_ids": sorted(nodes)}


class SqliteFederatedBudgetAuthority:
    """Atomically reserves global and tenant capacity and signs short-lived node grants."""

    def __init__(
        self, path: str | Path, catalog: SchemaCatalog, authority_id: str, key_id: str,
        policy_hash: str, global_limits: dict[str, int], tenant_limits: dict[str, dict[str, int]],
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.path, self.catalog, self.authority_id, self.key_id = Path(path), catalog, authority_id, key_id
        self.policy_hash = policy_hash
        self.global_limits, self.tenant_limits = copy.deepcopy(global_limits), copy.deepcopy(tenant_limits)
        self.private_key = private_key or Ed25519PrivateKey.generate()
        if not self.global_limits or any(value < 0 for value in self.global_limits.values()):
            raise ANOError("FEDERATED_BUDGET_POLICY_INVALID", "global budget limits are invalid")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("""CREATE TABLE IF NOT EXISTS federated_allocations (
                allocation_id TEXT PRIMARY KEY, request_id TEXT UNIQUE NOT NULL, request_hash TEXT NOT NULL,
                tenant_id TEXT NOT NULL, node_id TEXT NOT NULL, amounts_json TEXT NOT NULL,
                status TEXT NOT NULL, expires_at TEXT NOT NULL, allocation_json TEXT NOT NULL)""")
            connection.commit()
        finally:
            connection.close()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def allocate(
        self, request_id: str, node_id: str, tenant_id: str, amounts: dict[str, int], *,
        now: datetime | None = None, ttl_seconds: int = 60,
    ) -> dict[str, Any]:
        if ttl_seconds < 1 or ttl_seconds > 300 or not amounts or any(not isinstance(v, int) or v < 0 for v in amounts.values()):
            raise ANOError("FEDERATED_BUDGET_REQUEST_INVALID", "allocation amounts or TTL are invalid")
        if tenant_id not in self.tenant_limits or not set(amounts).issubset(self.global_limits) or not set(amounts).issubset(self.tenant_limits[tenant_id]):
            raise ANOError("FEDERATED_BUDGET_SCOPE_INVALID", "tenant or budget dimension is outside policy")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        request_hash = sha256_json({"node_id": node_id, "tenant_id": tenant_id, "amounts": amounts, "ttl_seconds": ttl_seconds})
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute("SELECT request_hash,allocation_json FROM federated_allocations WHERE request_id=?", (request_id,)).fetchone()
            if existing is not None:
                if existing["request_hash"] != request_hash:
                    raise ANOError("FEDERATED_BUDGET_IDEMPOTENCY_CONFLICT", "request ID is bound to another allocation")
                connection.commit()
                return json.loads(existing["allocation_json"])
            connection.execute("UPDATE federated_allocations SET status='expired' WHERE status='reserved' AND expires_at<=?", (_stamp(current),))
            rows = connection.execute("SELECT tenant_id,amounts_json FROM federated_allocations WHERE status='reserved'").fetchall()
            global_used = {key: 0 for key in self.global_limits}
            tenant_used = {key: 0 for key in self.global_limits}
            for row in rows:
                stored = json.loads(row["amounts_json"])
                for dimension, value in stored.items():
                    global_used[dimension] += int(value)
                    if row["tenant_id"] == tenant_id:
                        tenant_used[dimension] += int(value)
            for dimension, amount in amounts.items():
                if global_used[dimension] + amount > self.global_limits[dimension]:
                    raise ANOError("FEDERATED_GLOBAL_BUDGET_EXCEEDED", "allocation exceeds global capacity")
                if tenant_used[dimension] + amount > self.tenant_limits[tenant_id][dimension]:
                    raise ANOError("FEDERATED_TENANT_BUDGET_EXCEEDED", "allocation exceeds tenant capacity")
            material = {
                "allocation_id": new_id("fba"), "schema_version": "0.5.0", "request_id": request_id,
                "authority_id": self.authority_id, "policy_hash": self.policy_hash,
                "node_id": node_id, "tenant_id": tenant_id,
                "amounts": dict(sorted(amounts.items())), "issued_at": _stamp(current),
                "expires_at": _stamp(current + timedelta(seconds=ttl_seconds)), "key_id": self.key_id,
            }
            allocation = {**material, "signature": _sign(material, self.private_key)}
            self.catalog.validate("federated-budget-allocation", allocation)
            connection.execute(
                "INSERT INTO federated_allocations VALUES(?,?,?,?,?,?,?,?,?)",
                (allocation["allocation_id"], request_id, request_hash, tenant_id, node_id,
                 canonical_json(amounts), "reserved", allocation["expires_at"], canonical_json(allocation)),
            )
            connection.commit()
            return allocation
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class FederatedBudgetGrantVerifier:
    def __init__(self, catalog: SchemaCatalog, authority_id: str, key_id: str, policy_hash: str, public_key: Ed25519PublicKey) -> None:
        self.catalog, self.authority_id, self.key_id, self.policy_hash, self.public_key = catalog, authority_id, key_id, policy_hash, public_key

    def verify(
        self, allocation: dict[str, Any], *, node_id: str, tenant_id: str,
        now: datetime | None = None,
    ) -> None:
        self.catalog.validate("federated-budget-allocation", allocation)
        if allocation["authority_id"] != self.authority_id or allocation["key_id"] != self.key_id or allocation["policy_hash"] != self.policy_hash:
            raise ANOError("FEDERATED_BUDGET_AUTHORITY_UNTRUSTED", "allocation authority or key is not trusted")
        _verify(allocation, self.public_key, "FEDERATED_BUDGET_SIGNATURE_INVALID")
        if allocation["node_id"] != node_id or allocation["tenant_id"] != tenant_id:
            raise ANOError("FEDERATED_BUDGET_BINDING_MISMATCH", "allocation was rebound to another node or tenant")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if parse_timestamp(allocation["expires_at"]) <= current:
            raise ANOError("FEDERATED_BUDGET_EXPIRED", "allocation has expired")


class NodeSloReportSigner:
    def __init__(self, catalog: SchemaCatalog, node_id: str, key_id: str, private_key: Ed25519PrivateKey | None = None) -> None:
        self.catalog, self.node_id, self.key_id = catalog, node_id, key_id
        self.private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def report(
        self, tenant_id: str, service: str, sequence: int, *, window_start: datetime, window_end: datetime,
        sample_count: int, success_count: int, latency_p95_ms: float,
    ) -> dict[str, Any]:
        if sequence < 1 or sample_count < 1 or not 0 <= success_count <= sample_count or latency_p95_ms < 0 or not math.isfinite(latency_p95_ms):
            raise ANOError("FEDERATED_SLO_REPORT_INVALID", "node SLO metrics are invalid")
        material = {
            "report_id": new_id("nsr"), "schema_version": "0.5.0", "node_id": self.node_id,
            "tenant_id": tenant_id, "service": service, "sequence": sequence,
            "window_start": _stamp(window_start), "window_end": _stamp(window_end),
            "sample_count": sample_count, "success_count": success_count,
            "p95_latency_ms": latency_p95_ms, "key_id": self.key_id,
        }
        result = {**material, "signature": _sign(material, self.private_key)}
        self.catalog.validate("node-slo-report", result)
        return result


class SqliteFederatedSloController:
    def __init__(
        self, path: str | Path, catalog: SchemaCatalog,
        trusted_nodes: dict[str, tuple[str, str, Ed25519PublicKey]], *,
        policy_hash: str, targets: dict[str, dict[str, Any]],
    ) -> None:
        self.path, self.catalog, self.trusted_nodes = Path(path), catalog, dict(trusted_nodes)
        self.policy_hash, self.targets = policy_hash, copy.deepcopy(targets)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS federated_slo_cursors (
                    node_id TEXT NOT NULL, tenant_id TEXT NOT NULL, service TEXT NOT NULL,
                    sequence INTEGER NOT NULL, PRIMARY KEY(node_id,tenant_id,service));
                CREATE TABLE IF NOT EXISTS federated_slo_state (
                    tenant_id TEXT NOT NULL, service TEXT NOT NULL, operating_mode TEXT NOT NULL,
                    healthy_streak INTEGER NOT NULL, last_window_end TEXT NOT NULL,
                    PRIMARY KEY(tenant_id,service));
            """)
            connection.commit()
        finally:
            connection.close()

    def evaluate(
        self, tenant_id: str, service: str, reports: list[dict[str, Any]], *,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        target = self.targets.get(f"{tenant_id}:{service}")
        if target is None:
            raise ANOError("FEDERATED_SLO_TARGET_UNKNOWN", "tenant and service have no signed federation SLO target")
        availability_target = float(target["availability_target"])
        p95_latency_target_ms = float(target["p95_latency_target_ms"])
        minimum_nodes = int(target["minimum_nodes"])
        recovery_windows = int(target["recovery_windows"])
        if not 0 < availability_target < 1 or p95_latency_target_ms < 0 or minimum_nodes < 1 or recovery_windows < 1:
            raise ANOError("FEDERATED_SLO_TARGET_INVALID", "federated SLO target is invalid")
        nodes, domains = set(), set()
        scope: tuple[str, str] | None = None
        verified: list[dict[str, Any]] = []
        for report in reports:
            self.catalog.validate("node-slo-report", report)
            trust = self.trusted_nodes.get(report["node_id"])
            if trust is None or trust[1] != report["key_id"]:
                raise ANOError("FEDERATED_SLO_NODE_UNTRUSTED", "SLO report node or key is not trusted")
            _verify(report, trust[2], "FEDERATED_SLO_SIGNATURE_INVALID")
            if report["tenant_id"] != tenant_id or report["service"] != service:
                raise ANOError("FEDERATED_SLO_SCOPE_MISMATCH", "SLO report belongs to another tenant or service")
            report_scope = (report["window_start"], report["window_end"])
            if scope is not None and report_scope != scope:
                raise ANOError("FEDERATED_SLO_WINDOW_MISMATCH", "node reports cover different windows")
            scope = report_scope
            if report["node_id"] in nodes or trust[0] in domains:
                raise ANOError("FEDERATED_SLO_NOT_INDEPENDENT", "SLO report repeats a node or failure domain")
            nodes.add(report["node_id"]); domains.add(trust[0]); verified.append(report)
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if len(nodes) < minimum_nodes:
            window_end = scope[1] if scope else _stamp(current)
            connection = sqlite3.connect(self.path)
            try:
                connection.execute(
                    "INSERT INTO federated_slo_state VALUES(?,?,?,?,?) ON CONFLICT(tenant_id,service) DO UPDATE SET operating_mode='degraded',healthy_streak=0,last_window_end=excluded.last_window_end",
                    (tenant_id, service, "degraded", 0, window_end),
                )
                connection.commit()
            finally:
                connection.close()
            return self._decision(
                tenant_id, service, "unknown", "degraded", "safe_degrade", 0, 0, 0.0, 0.0,
                scope[0] if scope else _stamp(current), window_end, current,
            )
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            for report in verified:
                cursor = connection.execute(
                    "SELECT sequence FROM federated_slo_cursors WHERE node_id=? AND tenant_id=? AND service=?",
                    (report["node_id"], tenant_id, service),
                ).fetchone()
                if cursor is not None and report["sequence"] <= int(cursor["sequence"]):
                    raise ANOError("FEDERATED_SLO_REPLAY", "node SLO sequence did not advance")
            total = sum(int(item["sample_count"]) for item in verified)
            successes = sum(int(item["success_count"]) for item in verified)
            failures = total - successes
            availability = successes / total
            p95 = max(float(item["p95_latency_ms"]) for item in verified)
            allowed_failures = total * (1 - availability_target)
            burn = failures / allowed_failures if allowed_failures > 0 else (0.0 if failures == 0 else 1e9)
            violated = burn > 1.0 or p95 > p95_latency_target_ms
            state = connection.execute("SELECT * FROM federated_slo_state WHERE tenant_id=? AND service=?", (tenant_id, service)).fetchone()
            if state is not None and parse_timestamp(scope[1]) <= parse_timestamp(str(state["last_window_end"])):
                raise ANOError("FEDERATED_SLO_WINDOW_REPLAY", "SLO window did not advance")
            previous_mode = "normal" if state is None else str(state["operating_mode"])
            healthy_streak = 0 if state is None else int(state["healthy_streak"])
            if violated:
                mode, action, healthy_streak, status = "degraded", "degrade", 0, "violated"
            elif previous_mode == "degraded":
                healthy_streak += 1
                if healthy_streak >= recovery_windows:
                    mode, action, healthy_streak = "normal", "recover", 0
                else:
                    mode, action = "degraded", "hold"
                status = "met"
            else:
                mode, action, healthy_streak, status = "normal", "none", 0, "met"
            for report in verified:
                connection.execute(
                    "INSERT INTO federated_slo_cursors VALUES(?,?,?,?) ON CONFLICT(node_id,tenant_id,service) DO UPDATE SET sequence=excluded.sequence",
                    (report["node_id"], tenant_id, service, report["sequence"]),
                )
            connection.execute(
                "INSERT INTO federated_slo_state VALUES(?,?,?,?,?) ON CONFLICT(tenant_id,service) DO UPDATE SET operating_mode=excluded.operating_mode,healthy_streak=excluded.healthy_streak,last_window_end=excluded.last_window_end",
                (tenant_id, service, mode, healthy_streak, scope[1]),
            )
            decision = self._decision(tenant_id, service, status, mode, action, total, failures, availability, burn, scope[0], scope[1], current, p95)
            connection.commit()
            return decision
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def _decision(
        self, tenant_id: str, service: str, status: str, mode: str, action: str,
        sample_count: int, failure_count: int, availability: float, burn_rate: float,
        window_start: str, window_end: str, current: datetime, p95: float = 0.0,
    ) -> dict[str, Any]:
        result = {
            "decision_id": new_id("fsd"), "schema_version": "0.5.0",
            "policy_hash": self.policy_hash, "target_hash": sha256_json(self.targets[f"{tenant_id}:{service}"]),
            "tenant_id": tenant_id,
            "service": service, "window_start": window_start, "window_end": window_end,
            "sample_count": sample_count, "failure_count": failure_count, "availability": availability,
            "p95_latency_ms": p95, "error_budget_burn_rate": burn_rate, "status": status,
            "operating_mode": mode, "action": action, "decided_at": _stamp(current),
        }
        self.catalog.validate("federated-slo-decision", result)
        return result


class LearningWithdrawalSigner:
    def __init__(
        self, catalog: SchemaCatalog, issuer: str, key_id: str, federation_id: str, policy_hash: str,
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.catalog, self.issuer, self.key_id = catalog, issuer, key_id
        self.federation_id, self.policy_hash = federation_id, policy_hash
        self.private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def create(
        self, source_id: str, source_version: int, expected_assets: dict[str, list[str]], *,
        reason: str, malicious: bool, now: datetime | None = None,
    ) -> dict[str, Any]:
        material = {
            "withdrawal_id": new_id("lwd"), "schema_version": "0.5.0", "source_id": source_id,
            "federation_id": self.federation_id, "policy_hash": self.policy_hash,
            "source_version": source_version, "reason": reason, "malicious": malicious,
            "expected_assets": {key: sorted(set(value)) for key, value in sorted(expected_assets.items())},
            "issuer": self.issuer, "key_id": self.key_id,
            "issued_at": _stamp(now or datetime.now(timezone.utc)),
        }
        signed = {**material, "event_hash": sha256_json(material)}
        result = {**signed, "signature": _sign(signed, self.private_key)}
        self.catalog.validate("learning-withdrawal-event", result)
        return result


class LearningWithdrawalVerifier:
    def __init__(
        self, catalog: SchemaCatalog, trusted_issuers: set[str], trusted_keys: dict[str, Ed25519PublicKey], *,
        federation_id: str, policy_hash: str,
    ) -> None:
        self.catalog, self.trusted_issuers, self.trusted_keys = catalog, set(trusted_issuers), dict(trusted_keys)
        self.federation_id, self.policy_hash = federation_id, policy_hash

    def verify(self, event: dict[str, Any]) -> None:
        self.catalog.validate("learning-withdrawal-event", event)
        if event["issuer"] not in self.trusted_issuers or event["key_id"] not in self.trusted_keys:
            raise ANOError("LEARNING_WITHDRAWAL_UNTRUSTED", "withdrawal issuer or key is not trusted")
        if event["federation_id"] != self.federation_id or event["policy_hash"] != self.policy_hash:
            raise ANOError("LEARNING_WITHDRAWAL_POLICY_MISMATCH", "withdrawal is bound to another federation policy view")
        _verify(event, self.trusted_keys[event["key_id"]], "LEARNING_WITHDRAWAL_SIGNATURE_INVALID")
        signed = copy.deepcopy(event); signed.pop("signature"); event_hash = signed.pop("event_hash")
        if event_hash != sha256_json(signed):
            raise ANOError("LEARNING_WITHDRAWAL_HASH_INVALID", "withdrawal hash does not bind its content")


class SqliteFederatedLineageNode:
    def __init__(
        self, path: str | Path, catalog: SchemaCatalog, node_id: str, verifier: LearningWithdrawalVerifier,
        node_key_id: str, node_private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.path, self.catalog, self.node_id, self.verifier = Path(path), catalog, node_id, verifier
        self.node_key_id, self.node_private_key = node_key_id, node_private_key or Ed25519PrivateKey.generate()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS federated_assets (
                    asset_id TEXT PRIMARY KEY, source_id TEXT NOT NULL, asset_type TEXT NOT NULL, status TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS federated_withdrawals (
                    source_id TEXT PRIMARY KEY, source_version INTEGER NOT NULL,
                    event_hash TEXT NOT NULL, event_json TEXT NOT NULL, receipt_json TEXT NOT NULL);
            """)
            connection.commit()
        finally:
            connection.close()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.node_private_key.public_key()

    def register_asset(self, source_id: str, asset_id: str, asset_type: str) -> None:
        connection = sqlite3.connect(self.path)
        try:
            withdrawn = connection.execute("SELECT 1 FROM federated_withdrawals WHERE source_id=?", (source_id,)).fetchone() is not None
            connection.execute(
                "INSERT INTO federated_assets VALUES(?,?,?,?)",
                (asset_id, source_id, asset_type, "invalidated" if withdrawn else "active"),
            )
            connection.commit()
        finally:
            connection.close()

    def asset_status(self, asset_id: str) -> str:
        connection = sqlite3.connect(self.path)
        try:
            row = connection.execute("SELECT status FROM federated_assets WHERE asset_id=?", (asset_id,)).fetchone()
            if row is None:
                raise ANOError("FEDERATED_ASSET_UNKNOWN", "asset is not registered on this node")
            return str(row[0])
        finally:
            connection.close()

    def apply(self, event: dict[str, Any], *, now: datetime | None = None) -> dict[str, Any]:
        self.verifier.verify(event)
        expected = event["expected_assets"].get(self.node_id)
        if expected is None:
            raise ANOError("LEARNING_WITHDRAWAL_NODE_UNSCOPED", "withdrawal does not cover this node")
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("BEGIN IMMEDIATE")
            prior = connection.execute("SELECT source_version,event_hash FROM federated_withdrawals WHERE source_id=?", (event["source_id"],)).fetchone()
            if prior is not None and (
                event["source_version"] < int(prior["source_version"])
                or (event["source_version"] == int(prior["source_version"]) and event["event_hash"] != prior["event_hash"])
            ):
                raise ANOError("LEARNING_WITHDRAWAL_STALE", "withdrawal version regressed or equivocated")
            connection.execute("UPDATE federated_assets SET status='invalidated' WHERE source_id=?", (event["source_id"],))
            rows = connection.execute("SELECT asset_id FROM federated_assets WHERE source_id=? AND status='invalidated'", (event["source_id"],)).fetchall()
            invalidated = sorted(str(row["asset_id"]) for row in rows)
            unresolved = sorted(set(expected) - set(invalidated))
            material = {
                "receipt_id": new_id("lwr"), "schema_version": "0.5.0", "withdrawal_id": event["withdrawal_id"],
                "event_hash": event["event_hash"], "source_id": event["source_id"], "source_version": event["source_version"],
                "node_id": self.node_id, "invalidated_asset_ids": invalidated, "unresolved_asset_ids": unresolved,
                "status": "complete" if not unresolved else "incomplete", "key_id": self.node_key_id,
                "applied_at": _stamp(now or datetime.now(timezone.utc)),
            }
            receipt = {**material, "signature": _sign(material, self.node_private_key)}
            self.catalog.validate("learning-withdrawal-receipt", receipt)
            connection.execute(
                "INSERT INTO federated_withdrawals VALUES(?,?,?,?,?) ON CONFLICT(source_id) DO UPDATE SET source_version=excluded.source_version,event_hash=excluded.event_hash,event_json=excluded.event_json,receipt_json=excluded.receipt_json",
                (event["source_id"], event["source_version"], event["event_hash"], canonical_json(event), canonical_json(receipt)),
            )
            connection.commit()
            return receipt
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class LearningWithdrawalReconciler:
    def __init__(
        self, catalog: SchemaCatalog,
        trusted_nodes: dict[str, tuple[str, Ed25519PublicKey]],
    ) -> None:
        self.catalog, self.trusted_nodes = catalog, dict(trusted_nodes)

    def reconcile(self, event: dict[str, Any], receipts: list[dict[str, Any]]) -> dict[str, Any]:
        by_node: dict[str, dict[str, Any]] = {}
        for receipt in receipts:
            self.catalog.validate("learning-withdrawal-receipt", receipt)
            trust = self.trusted_nodes.get(receipt["node_id"])
            if trust is None or trust[0] != receipt["key_id"]:
                raise ANOError("LEARNING_RECEIPT_UNTRUSTED", "withdrawal receipt node or key is not trusted")
            _verify(receipt, trust[1], "LEARNING_RECEIPT_SIGNATURE_INVALID")
            if receipt["node_id"] in by_node:
                raise ANOError("LEARNING_RECEIPT_DUPLICATE", "node supplied multiple withdrawal receipts")
            if receipt["event_hash"] != event["event_hash"] or receipt["withdrawal_id"] != event["withdrawal_id"]:
                raise ANOError("LEARNING_RECEIPT_BINDING_MISMATCH", "receipt belongs to another withdrawal")
            by_node[receipt["node_id"]] = receipt
        required = set(event["expected_assets"])
        if set(by_node) != required:
            raise ANOError("LEARNING_PROPAGATION_INCOMPLETE", "withdrawal receipts do not cover every required node")
        for node_id, expected in event["expected_assets"].items():
            receipt = by_node[node_id]
            if receipt["status"] != "complete" or receipt["unresolved_asset_ids"] or not set(expected).issubset(receipt["invalidated_asset_ids"]):
                raise ANOError("LEARNING_PROPAGATION_INCOMPLETE", "node did not invalidate all expected derived assets")
        return {
            "withdrawal_id": event["withdrawal_id"], "event_hash": event["event_hash"],
            "status": "complete", "node_ids": sorted(by_node),
            "invalidated_asset_ids": sorted({item for receipt in receipts for item in receipt["invalidated_asset_ids"]}),
        }
