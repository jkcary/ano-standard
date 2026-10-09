from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

from .tenant_storage import TenantSession


@runtime_checkable
class TenantStateStoreAdapter(Protocol):
    """Minimum portable state-store surface required by the ANO 0.4 conformance contract."""

    def put(
        self, session: TenantSession, namespace: str, object_id: str, payload: dict[str, Any], *,
        expected_version: int, idempotency_key: str,
    ) -> dict[str, Any]: ...

    def delete(
        self, session: TenantSession, namespace: str, object_id: str, *,
        expected_version: int, idempotency_key: str,
    ) -> dict[str, Any]: ...

    def get(
        self, session: TenantSession, namespace: str, object_id: str, *, include_deleted: bool = False,
    ) -> dict[str, Any]: ...

    def list_objects(
        self, session: TenantSession, namespace: str, *, include_deleted: bool = False,
    ) -> tuple[dict[str, Any], ...]: ...

    def verify_tenant_log(self, session: TenantSession, *, expected_head_hash: str | None = None) -> None: ...

    def export_tenant(self, session: TenantSession) -> dict[str, Any]: ...

    def capabilities(self) -> dict[str, Any]: ...


@runtime_checkable
class DistributedOperationStoreAdapter(Protocol):
    """ANO 0.5 portable surface for fenced transactional delivery stores."""

    def capabilities(self) -> dict[str, Any]: ...

    def acquire_lease(self, resource_id: str, node_id: str, **kwargs: Any) -> dict[str, Any]: ...

    def execute_operation(
        self, tenant_id: str, operation_id: str, state: dict[str, Any],
        publishes: list[dict[str, Any]], **kwargs: Any,
    ) -> dict[str, Any]: ...

    def claim_next(
        self, lease: dict[str, Any], topics: list[str], tenant_ids: list[str], **kwargs: Any,
    ) -> dict[str, Any] | None: ...

    def complete(
        self, lease: dict[str, Any], message_id: str, consumer_id: str,
        effect: dict[str, Any], **kwargs: Any,
    ) -> dict[str, Any]: ...

    def recover(self, **kwargs: Any) -> dict[str, Any]: ...
