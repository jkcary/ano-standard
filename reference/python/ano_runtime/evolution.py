from __future__ import annotations

import base64
import copy
import json
import sqlite3
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import ANOError
from .schema import SchemaCatalog
from .util import canonical_json, new_id, sha256_json, utc_now


class CapabilityPackageSigner:
    """Build immutable, content-addressed capability packages signed by a release identity."""

    def __init__(
        self, catalog: SchemaCatalog, issuer: str, key_id: str,
        private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        self.catalog = catalog
        self.issuer = issuer
        self.key_id = key_id
        self.private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def create(
        self, *, component_id: str, generation: int, kind: str, artifact_hash: str,
        manifest_hash: str, capabilities: list[str], required_permissions: list[str],
        budget_ceiling: dict[str, int], source_adapter_id: str, evidence_ids: list[str],
        goal_contract_hash: str, evaluator_hash: str, rollback_package_id: str | None,
    ) -> dict[str, Any]:
        material = {
            "package_id": new_id("cpkg"), "schema_version": "0.5.0", "component_id": component_id,
            "generation": generation, "kind": kind, "artifact_hash": artifact_hash,
            "manifest_hash": manifest_hash, "capabilities": sorted(set(capabilities)),
            "required_permissions": sorted(set(required_permissions)),
            "budget_ceiling": dict(sorted(budget_ceiling.items())), "source_adapter_id": source_adapter_id,
            "evidence_ids": sorted(set(evidence_ids)), "goal_contract_hash": goal_contract_hash,
            "evaluator_hash": evaluator_hash, "rollback_package_id": rollback_package_id,
            "issuer": self.issuer, "key_id": self.key_id, "created_at": utc_now(),
        }
        package_hash = sha256_json(material)
        signed = {**material, "package_hash": package_hash}
        package = {
            **signed,
            "signature": base64.b64encode(
                self.private_key.sign(canonical_json(signed).encode("utf-8")),
            ).decode("ascii"),
        }
        self.catalog.validate("capability-package", package)
        return package


class CapabilityPackageVerifier:
    def __init__(
        self, catalog: SchemaCatalog, *, trusted_issuers: set[str],
        trusted_keys: dict[str, Ed25519PublicKey],
    ) -> None:
        if not trusted_issuers or not trusted_keys:
            raise ANOError("CAPABILITY_TRUST_EMPTY", "capability package trust policy cannot be empty")
        self.catalog = catalog
        self.trusted_issuers = set(trusted_issuers)
        self.trusted_keys = dict(trusted_keys)

    def verify(self, package: dict[str, Any]) -> None:
        self.catalog.validate("capability-package", package)
        if package["issuer"] not in self.trusted_issuers:
            raise ANOError("CAPABILITY_ISSUER_UNTRUSTED", "capability package issuer is not trusted")
        key = self.trusted_keys.get(package["key_id"])
        if key is None:
            raise ANOError("CAPABILITY_KEY_UNTRUSTED", "capability package key is not trusted")
        signed = copy.deepcopy(package)
        signature_text = signed.pop("signature")
        material = copy.deepcopy(signed)
        package_hash = material.pop("package_hash")
        if package_hash != sha256_json(material):
            raise ANOError("CAPABILITY_PACKAGE_HASH_INVALID", "capability package content hash is invalid")
        try:
            signature = base64.b64decode(signature_text, validate=True)
            key.verify(signature, canonical_json(signed).encode("utf-8"))
        except (ValueError, InvalidSignature) as exc:
            raise ANOError("CAPABILITY_SIGNATURE_INVALID", "capability package signature is invalid") from exc


class PersistentEvolutionKernel:
    """Crash-safe evolution state machine with approval gates, baseline fencing and rollback."""

    _INCOMPLETE = ("proposed", "evaluated", "approved", "staged")

    def __init__(
        self, path: str | Path, catalog: SchemaCatalog, verifier: CapabilityPackageVerifier, *,
        component_policies: dict[str, dict[str, Any]],
    ) -> None:
        self.path = Path(path)
        self.catalog = catalog
        self.verifier = verifier
        self.component_policies = copy.deepcopy(component_policies)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = FULL")
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS capability_packages (
                    package_id TEXT PRIMARY KEY, component_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    package_hash TEXT NOT NULL, package_json TEXT NOT NULL, registered_at TEXT NOT NULL,
                    UNIQUE (component_id, generation)
                );
                CREATE TABLE IF NOT EXISTS evolution_transactions (
                    transaction_id TEXT PRIMARY KEY, component_id TEXT NOT NULL,
                    from_package_id TEXT, to_package_id TEXT NOT NULL, status TEXT NOT NULL,
                    goal_contract_hash TEXT NOT NULL, evaluator_hash TEXT NOT NULL,
                    evaluation_report_ids_json TEXT NOT NULL, approval_ids_json TEXT NOT NULL,
                    approver_ids_json TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS active_capability_packages (
                    component_id TEXT PRIMARY KEY, package_id TEXT NOT NULL, generation INTEGER NOT NULL,
                    activated_by_transaction_id TEXT NOT NULL, activated_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS evolution_events (
                    component_id TEXT NOT NULL, sequence INTEGER NOT NULL, event_id TEXT NOT NULL,
                    transaction_id TEXT NOT NULL, event_type TEXT NOT NULL, transaction_status TEXT NOT NULL,
                    detail_hash TEXT NOT NULL, previous_hash TEXT, recorded_at TEXT NOT NULL,
                    record_hash TEXT NOT NULL, PRIMARY KEY (component_id, sequence), UNIQUE(event_id)
                );
                """
            )
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def _policy(self, component_id: str) -> dict[str, Any]:
        policy = self.component_policies.get(component_id)
        if policy is None:
            raise ANOError("EVOLUTION_COMPONENT_UNKNOWN", "component has no evolution policy")
        minimum = policy.get("minimum_approvals")
        if not isinstance(minimum, int) or minimum < 1:
            raise ANOError("EVOLUTION_POLICY_INVALID", "component approval threshold is invalid")
        return policy

    @staticmethod
    def _event_hash(event: dict[str, Any]) -> str:
        material = copy.deepcopy(event)
        material.pop("record_hash", None)
        return sha256_json(material)

    def _append_event(
        self, connection: sqlite3.Connection, transaction: dict[str, Any], event_type: str,
        details: dict[str, Any],
    ) -> dict[str, Any]:
        previous = connection.execute(
            "SELECT sequence, record_hash FROM evolution_events WHERE component_id = ? ORDER BY sequence DESC LIMIT 1",
            (transaction["component_id"],),
        ).fetchone()
        sequence = 1 if previous is None else int(previous["sequence"]) + 1
        event_material = {
            "event_id": new_id("eev"), "schema_version": "0.5.0",
            "component_id": transaction["component_id"], "transaction_id": transaction["transaction_id"],
            "sequence": sequence, "event_type": event_type, "transaction_status": transaction["status"],
            "detail_hash": sha256_json(details),
            "previous_hash": None if previous is None else str(previous["record_hash"]),
            "recorded_at": transaction["updated_at"],
        }
        event = {**event_material, "record_hash": self._event_hash(event_material)}
        self.catalog.validate("evolution-event", event)
        connection.execute(
            """INSERT INTO evolution_events
               (component_id, sequence, event_id, transaction_id, event_type, transaction_status,
                detail_hash, previous_hash, recorded_at, record_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                event["component_id"], sequence, event["event_id"], event["transaction_id"], event_type,
                event["transaction_status"], event["detail_hash"], event["previous_hash"],
                event["recorded_at"], event["record_hash"],
            ),
        )
        return event

    def _package(self, connection: sqlite3.Connection, package_id: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT package_hash, package_json FROM capability_packages WHERE package_id = ?", (package_id,),
        ).fetchone()
        if row is None:
            raise ANOError("CAPABILITY_PACKAGE_UNKNOWN", "capability package is not registered")
        try:
            package = json.loads(row["package_json"])
            if row["package_hash"] != package["package_hash"]:
                raise ValueError("stored package hash mismatch")
            self.verifier.verify(package)
        except (json.JSONDecodeError, KeyError, ValueError, ANOError) as exc:
            if isinstance(exc, ANOError) and exc.code == "CAPABILITY_PACKAGE_UNKNOWN":
                raise
            raise ANOError("CAPABILITY_PACKAGE_CORRUPT", "registered capability package failed integrity verification") from exc
        return package

    @staticmethod
    def _transaction(row: sqlite3.Row) -> dict[str, Any]:
        return {
            "transaction_id": row["transaction_id"], "schema_version": "0.5.0",
            "component_id": row["component_id"], "from_package_id": row["from_package_id"],
            "to_package_id": row["to_package_id"], "status": row["status"],
            "goal_contract_hash": row["goal_contract_hash"], "evaluator_hash": row["evaluator_hash"],
            "evaluation_report_ids": json.loads(row["evaluation_report_ids_json"]),
            "approval_ids": json.loads(row["approval_ids_json"]),
            "approver_ids": json.loads(row["approver_ids_json"]),
            "created_at": row["created_at"], "updated_at": row["updated_at"],
        }

    def _get_transaction(self, connection: sqlite3.Connection, transaction_id: str) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM evolution_transactions WHERE transaction_id = ?", (transaction_id,),
        ).fetchone()
        if row is None:
            raise ANOError("EVOLUTION_TRANSACTION_UNKNOWN", "evolution transaction is unknown")
        transaction = self._transaction(row)
        try:
            self.catalog.validate("evolution-transaction", transaction)
            target = self._package(connection, transaction["to_package_id"])
            if (
                target["component_id"] != transaction["component_id"]
                or target["goal_contract_hash"] != transaction["goal_contract_hash"]
                or target["evaluator_hash"] != transaction["evaluator_hash"]
            ):
                raise ValueError("transaction-to-package binding mismatch")
            event_row = connection.execute(
                """SELECT * FROM evolution_events WHERE component_id = ? AND transaction_id = ?
                   ORDER BY sequence DESC LIMIT 1""",
                (transaction["component_id"], transaction_id),
            ).fetchone()
            if event_row is None:
                raise ValueError("transaction has no evolution event")
            event = {key: event_row[key] for key in event_row.keys()} | {"schema_version": "0.5.0"}
            self.catalog.validate("evolution-event", event)
            if (
                event["record_hash"] != self._event_hash(event)
                or event["transaction_status"] != transaction["status"]
                or event["transaction_id"] != transaction_id
            ):
                raise ValueError("transaction-to-event binding mismatch")
            expected_details: dict[str, Any] | None = None
            if transaction["status"] == "proposed":
                expected_details = {
                    "from_package_id": transaction["from_package_id"],
                    "to_package_id": transaction["to_package_id"],
                }
            elif transaction["status"] in {"evaluated", "rejected"}:
                expected_details = {
                    "report_ids": transaction["evaluation_report_ids"],
                    "passed": transaction["status"] == "evaluated",
                }
            elif transaction["status"] == "approved":
                expected_details = {
                    "approval_ids": transaction["approval_ids"],
                    "approver_ids": transaction["approver_ids"],
                }
            elif transaction["status"] == "staged":
                expected_details = {"package_id": transaction["to_package_id"]}
            elif transaction["status"] == "active":
                expected_details = {
                    "package_id": target["package_id"], "package_hash": target["package_hash"],
                }
            if expected_details is not None and event["detail_hash"] != sha256_json(expected_details):
                raise ValueError("transaction detail projection differs from its event")
        except (ANOError, KeyError, TypeError, ValueError) as exc:
            raise ANOError("EVOLUTION_TRANSACTION_CORRUPT", "evolution transaction integrity verification failed") from exc
        return transaction

    def _save_transaction(self, connection: sqlite3.Connection, transaction: dict[str, Any]) -> None:
        self.catalog.validate("evolution-transaction", transaction)
        connection.execute(
            """UPDATE evolution_transactions SET status = ?, evaluation_report_ids_json = ?,
               approval_ids_json = ?, approver_ids_json = ?, updated_at = ? WHERE transaction_id = ?""",
            (
                transaction["status"], canonical_json(transaction["evaluation_report_ids"]),
                canonical_json(transaction["approval_ids"]), canonical_json(transaction["approver_ids"]),
                transaction["updated_at"], transaction["transaction_id"],
            ),
        )

    def register_package(self, package: dict[str, Any]) -> dict[str, Any]:
        self.verifier.verify(package)
        policy = self._policy(package["component_id"])
        allowed_permissions = set(policy.get("permission_ceiling", []))
        if not set(package["required_permissions"]).issubset(allowed_permissions):
            raise ANOError("EVOLUTION_PERMISSION_EXPANSION", "capability package exceeds component permission ceiling")
        budget_limit = policy.get("budget_ceiling", {})
        if not set(package["budget_ceiling"]).issubset(budget_limit) or any(
            package["budget_ceiling"][key] > budget_limit[key] for key in package["budget_ceiling"]
        ):
            raise ANOError("EVOLUTION_BUDGET_EXPANSION", "capability package exceeds component budget ceiling")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT package_hash, package_json FROM capability_packages WHERE package_id = ?",
                (package["package_id"],),
            ).fetchone()
            if existing is not None:
                if existing["package_hash"] != package["package_hash"]:
                    raise ANOError("CAPABILITY_PACKAGE_ID_CONFLICT", "package ID is bound to different content")
                connection.commit()
                return json.loads(existing["package_json"])
            maximum = connection.execute(
                "SELECT MAX(generation) AS maximum FROM capability_packages WHERE component_id = ?",
                (package["component_id"],),
            ).fetchone()
            if maximum is not None and maximum["maximum"] is not None and package["generation"] <= int(maximum["maximum"]):
                raise ANOError("EVOLUTION_GENERATION_CONFLICT", "capability package generation is not monotonic")
            rollback_id = package["rollback_package_id"]
            if rollback_id is not None:
                rollback = self._package(connection, rollback_id)
                if (
                    rollback["component_id"] != package["component_id"]
                    or rollback["generation"] >= package["generation"]
                ):
                    raise ANOError("EVOLUTION_ROLLBACK_INVALID", "rollback package is not an older package of the component")
            connection.execute(
                """INSERT INTO capability_packages
                   (package_id, component_id, generation, package_hash, package_json, registered_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    package["package_id"], package["component_id"], package["generation"],
                    package["package_hash"], canonical_json(package), utc_now(),
                ),
            )
            connection.commit()
            return copy.deepcopy(package)
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            raise ANOError("EVOLUTION_GENERATION_CONFLICT", "component generation is already registered") from exc
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def active_package(self, component_id: str) -> dict[str, Any] | None:
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT package_id FROM active_capability_packages WHERE component_id = ?", (component_id,),
            ).fetchone()
            return None if row is None else self._package(connection, str(row["package_id"]))
        finally:
            connection.close()

    def propose(
        self, to_package_id: str, *, expected_active_package_id: str | None,
    ) -> dict[str, Any]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            target = self._package(connection, to_package_id)
            active = connection.execute(
                "SELECT package_id FROM active_capability_packages WHERE component_id = ?",
                (target["component_id"],),
            ).fetchone()
            actual_active = None if active is None else str(active["package_id"])
            if actual_active != expected_active_package_id:
                raise ANOError("EVOLUTION_BASELINE_STALE", "active package differs from the proposed baseline")
            if actual_active is None and target["rollback_package_id"] is not None:
                raise ANOError("EVOLUTION_ROLLBACK_INVALID", "initial activation cannot name a rollback baseline")
            if actual_active is not None and target["rollback_package_id"] != actual_active:
                raise ANOError("EVOLUTION_ROLLBACK_INVALID", "upgrade must bind the current active package as rollback baseline")
            timestamp = utc_now()
            transaction = {
                "transaction_id": new_id("evtx"), "schema_version": "0.5.0",
                "component_id": target["component_id"], "from_package_id": actual_active,
                "to_package_id": to_package_id, "status": "proposed",
                "goal_contract_hash": target["goal_contract_hash"], "evaluator_hash": target["evaluator_hash"],
                "evaluation_report_ids": [], "approval_ids": [], "approver_ids": [],
                "created_at": timestamp, "updated_at": timestamp,
            }
            self.catalog.validate("evolution-transaction", transaction)
            connection.execute(
                """INSERT INTO evolution_transactions
                   (transaction_id, component_id, from_package_id, to_package_id, status,
                    goal_contract_hash, evaluator_hash, evaluation_report_ids_json,
                    approval_ids_json, approver_ids_json, created_at, updated_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, '[]', '[]', '[]', ?, ?)""",
                (
                    transaction["transaction_id"], transaction["component_id"], actual_active,
                    to_package_id, "proposed", transaction["goal_contract_hash"],
                    transaction["evaluator_hash"], timestamp, timestamp,
                ),
            )
            self._append_event(connection, transaction, "evolution.proposed", {
                "from_package_id": actual_active, "to_package_id": to_package_id,
            })
            connection.commit()
            return transaction
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def record_evaluation(
        self, transaction_id: str, *, report_ids: list[str], passed: bool,
        goal_contract_hash: str, evaluator_hash: str,
    ) -> dict[str, Any]:
        if not report_ids or len(report_ids) != len(set(report_ids)):
            raise ANOError("EVOLUTION_EVIDENCE_INVALID", "evaluation report IDs must be non-empty and unique")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction = self._get_transaction(connection, transaction_id)
            if transaction["status"] != "proposed":
                raise ANOError("EVOLUTION_STATE_INVALID", "only a proposed evolution can be evaluated")
            if (
                goal_contract_hash != transaction["goal_contract_hash"]
                or evaluator_hash != transaction["evaluator_hash"]
            ):
                raise ANOError("EVOLUTION_EVALUATION_BINDING_INVALID", "evaluation changed the goal or evaluator contract")
            transaction["evaluation_report_ids"] = sorted(report_ids)
            transaction["status"] = "evaluated" if passed else "rejected"
            transaction["updated_at"] = utc_now()
            self._save_transaction(connection, transaction)
            self._append_event(
                connection, transaction,
                "evolution.evaluated" if passed else "evolution.rejected",
                {"report_ids": transaction["evaluation_report_ids"], "passed": passed},
            )
            connection.commit()
            return transaction
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def approve(self, transaction_id: str, approvals: list[dict[str, str]]) -> dict[str, Any]:
        approval_ids = [item.get("approval_id", "") for item in approvals]
        approver_ids = [item.get("approver_id", "") for item in approvals]
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction = self._get_transaction(connection, transaction_id)
            if transaction["status"] != "evaluated":
                raise ANOError("EVOLUTION_STATE_INVALID", "only an evaluated evolution can be approved")
            required = int(self._policy(transaction["component_id"])["minimum_approvals"])
            if (
                len(approval_ids) < required or len(set(approval_ids)) != len(approval_ids)
                or len(set(approver_ids)) < required or any(not item for item in approval_ids + approver_ids)
            ):
                raise ANOError("EVOLUTION_APPROVAL_INSUFFICIENT", "independent approval threshold was not met")
            transaction["approval_ids"] = sorted(approval_ids)
            transaction["approver_ids"] = sorted(set(approver_ids))
            transaction["status"] = "approved"
            transaction["updated_at"] = utc_now()
            self._save_transaction(connection, transaction)
            self._append_event(connection, transaction, "evolution.approved", {
                "approval_ids": transaction["approval_ids"], "approver_ids": transaction["approver_ids"],
            })
            connection.commit()
            return transaction
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def stage(self, transaction_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction = self._get_transaction(connection, transaction_id)
            if transaction["status"] != "approved":
                raise ANOError("EVOLUTION_STATE_INVALID", "only an approved evolution can be staged")
            transaction["status"] = "staged"
            transaction["updated_at"] = utc_now()
            self._save_transaction(connection, transaction)
            self._append_event(connection, transaction, "evolution.staged", {"package_id": transaction["to_package_id"]})
            connection.commit()
            return transaction
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def activate(self, transaction_id: str) -> dict[str, Any]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction = self._get_transaction(connection, transaction_id)
            if transaction["status"] != "staged":
                raise ANOError("EVOLUTION_STATE_INVALID", "only a staged evolution can be activated")
            target = self._package(connection, transaction["to_package_id"])
            active = connection.execute(
                "SELECT package_id FROM active_capability_packages WHERE component_id = ?",
                (transaction["component_id"],),
            ).fetchone()
            actual_active = None if active is None else str(active["package_id"])
            if actual_active != transaction["from_package_id"]:
                raise ANOError("EVOLUTION_FENCED", "another evolution changed the active baseline")
            transaction["status"] = "active"
            transaction["updated_at"] = utc_now()
            self._save_transaction(connection, transaction)
            connection.execute(
                """INSERT INTO active_capability_packages
                   (component_id, package_id, generation, activated_by_transaction_id, activated_at)
                   VALUES (?, ?, ?, ?, ?)
                   ON CONFLICT(component_id) DO UPDATE SET package_id=excluded.package_id,
                   generation=excluded.generation, activated_by_transaction_id=excluded.activated_by_transaction_id,
                   activated_at=excluded.activated_at""",
                (
                    transaction["component_id"], target["package_id"], target["generation"],
                    transaction_id, transaction["updated_at"],
                ),
            )
            self._append_event(connection, transaction, "evolution.activated", {
                "package_id": target["package_id"], "package_hash": target["package_hash"],
            })
            connection.commit()
            return transaction
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def rollback(self, transaction_id: str, *, reason: str) -> dict[str, Any]:
        if not reason.strip():
            raise ANOError("EVOLUTION_ROLLBACK_REASON_REQUIRED", "rollback reason cannot be empty")
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            transaction = self._get_transaction(connection, transaction_id)
            if transaction["status"] != "active" or transaction["from_package_id"] is None:
                raise ANOError("EVOLUTION_ROLLBACK_UNAVAILABLE", "active evolution has no rollback baseline")
            active = connection.execute(
                "SELECT package_id FROM active_capability_packages WHERE component_id = ?",
                (transaction["component_id"],),
            ).fetchone()
            if active is None or active["package_id"] != transaction["to_package_id"]:
                raise ANOError("EVOLUTION_FENCED", "active component no longer belongs to this evolution")
            baseline = self._package(connection, transaction["from_package_id"])
            transaction["status"] = "rolled_back"
            transaction["updated_at"] = utc_now()
            self._save_transaction(connection, transaction)
            connection.execute(
                """UPDATE active_capability_packages SET package_id = ?, generation = ?,
                   activated_by_transaction_id = ?, activated_at = ? WHERE component_id = ?""",
                (
                    baseline["package_id"], baseline["generation"], transaction_id,
                    transaction["updated_at"], transaction["component_id"],
                ),
            )
            self._append_event(connection, transaction, "evolution.rolled_back", {
                "restored_package_id": baseline["package_id"], "reason": reason,
            })
            connection.commit()
            return transaction
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def recover_incomplete(self) -> tuple[dict[str, Any], ...]:
        connection = self._connect()
        try:
            placeholders = ",".join("?" for _ in self._INCOMPLETE)
            rows = connection.execute(
                f"SELECT * FROM evolution_transactions WHERE status IN ({placeholders}) ORDER BY created_at",
                self._INCOMPLETE,
            ).fetchall()
            transactions = tuple(self._transaction(row) for row in rows)
            for transaction in transactions:
                self.catalog.validate("evolution-transaction", transaction)
            return transactions
        finally:
            connection.close()

    def events(self, component_id: str) -> tuple[dict[str, Any], ...]:
        connection = self._connect()
        try:
            rows = connection.execute(
                "SELECT * FROM evolution_events WHERE component_id = ? ORDER BY sequence", (component_id,),
            ).fetchall()
        finally:
            connection.close()
        return tuple({key: row[key] for key in row.keys()} | {"schema_version": "0.5.0"} for row in rows)

    def verify_log(self, component_id: str, *, expected_head_hash: str | None = None) -> None:
        previous_hash: str | None = None
        events = self.events(component_id)
        for sequence, event in enumerate(events, start=1):
            try:
                self.catalog.validate("evolution-event", event)
                if event["sequence"] != sequence or event["previous_hash"] != previous_hash:
                    raise ValueError("evolution chain discontinuity")
                if event["record_hash"] != self._event_hash(event):
                    raise ValueError("evolution record hash mismatch")
            except (ANOError, KeyError, TypeError, ValueError) as exc:
                raise ANOError("EVOLUTION_LOG_CORRUPT", "component evolution log verification failed") from exc
            previous_hash = event["record_hash"]
        if expected_head_hash is not None and previous_hash != expected_head_hash:
            raise ANOError("EVOLUTION_LOG_TRUNCATED", "evolution log head differs from its external anchor")

    def head_hash(self, component_id: str) -> str | None:
        events = self.events(component_id)
        return None if not events else str(events[-1]["record_hash"])


class ModelCapabilityPackageFactory:
    """Translate an evaluated model advancement into a candidate package without production authority."""

    def __init__(self, signer: CapabilityPackageSigner) -> None:
        self.signer = signer

    def build(
        self, advancement: dict[str, Any], *, component_id: str, generation: int,
        artifact_hash: str, manifest_hash: str, required_permissions: list[str],
        budget_ceiling: dict[str, int], goal_contract_hash: str, evaluator_hash: str,
        rollback_package_id: str | None,
    ) -> dict[str, Any]:
        if advancement.get("status") != "evaluated":
            raise ANOError("MODEL_ADVANCEMENT_NOT_EVALUATED", "only evaluated model advancements can form packages")
        capabilities = list(advancement.get("discovered_capabilities", []))
        if not capabilities:
            raise ANOError("MODEL_ADVANCEMENT_EMPTY", "model advancement exposes no verified capability")
        return self.signer.create(
            component_id=component_id, generation=generation, kind="model",
            artifact_hash=artifact_hash, manifest_hash=manifest_hash, capabilities=capabilities,
            required_permissions=required_permissions, budget_ceiling=budget_ceiling,
            source_adapter_id=str(advancement["candidate_adapter_id"]),
            evidence_ids=[str(advancement["advancement_id"])], goal_contract_hash=goal_contract_hash,
            evaluator_hash=evaluator_hash, rollback_package_id=rollback_package_id,
        )
