from __future__ import annotations

import base64
import copy
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .errors import ANOError
from .schema import SchemaCatalog
from .tenant_storage import TenantAccessBoundary, TenantSession
from .util import canonical_json, new_id, parse_timestamp


class Ed25519IdentityIssuer:
    """Test/reference issuer. Production verifiers consume public keys from external IdPs."""

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

    def issue(
        self, subject: str, audience: str, *, now: datetime | None = None, lifetime_seconds: int = 300,
    ) -> dict[str, Any]:
        if lifetime_seconds < 1 or lifetime_seconds > 900:
            raise ANOError("IDENTITY_LIFETIME_INVALID", "external assertion lifetime must be between 1 and 900 seconds")
        issued = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        claims = {
            "assertion_id": new_id("eid"), "schema_version": "0.4.0", "issuer": self.issuer,
            "subject": subject, "audience": audience, "key_id": self.key_id,
            "issued_at": issued.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "expires_at": (issued + timedelta(seconds=lifetime_seconds)).isoformat(
                timespec="milliseconds",
            ).replace("+00:00", "Z"),
        }
        assertion = {
            **claims,
            "signature": base64.b64encode(
                self.private_key.sign(canonical_json(claims).encode("utf-8")),
            ).decode("ascii"),
        }
        self.catalog.validate("external-identity-assertion", assertion)
        return assertion


class SqliteExternalIdentityVerifier:
    """Verify trusted Ed25519 assertions and consume each assertion once before issuing a tenant session."""

    def __init__(
        self, path: str | Path, catalog: SchemaCatalog, boundary: TenantAccessBoundary, *,
        expected_issuer: str, expected_audience: str, trusted_keys: dict[str, Ed25519PublicKey],
        clock_skew_seconds: int = 30,
    ) -> None:
        if not trusted_keys:
            raise ANOError("IDENTITY_TRUST_EMPTY", "at least one trusted identity key is required")
        self.path = Path(path)
        self.catalog = catalog
        self.boundary = boundary
        self.expected_issuer = expected_issuer
        self.expected_audience = expected_audience
        self.trusted_keys = dict(trusted_keys)
        self.clock_skew = timedelta(seconds=clock_skew_seconds)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS consumed_identity_assertions (
                   issuer TEXT NOT NULL, assertion_id TEXT NOT NULL, subject TEXT NOT NULL,
                   consumed_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                   PRIMARY KEY (issuer, assertion_id))"""
            )
            connection.commit()
        finally:
            connection.close()

    def verify_and_open(
        self, assertion: dict[str, Any], *, now: datetime | None = None,
    ) -> TenantSession:
        self.catalog.validate("external-identity-assertion", assertion)
        if assertion["issuer"] != self.expected_issuer or assertion["audience"] != self.expected_audience:
            raise ANOError("IDENTITY_TRUST_MISMATCH", "external assertion issuer or audience is not trusted")
        key = self.trusted_keys.get(assertion["key_id"])
        if key is None:
            raise ANOError("IDENTITY_KEY_UNTRUSTED", "external assertion signing key is not trusted")
        claims = copy.deepcopy(assertion)
        signature_text = claims.pop("signature")
        try:
            signature = base64.b64decode(signature_text, validate=True)
            key.verify(signature, canonical_json(claims).encode("utf-8"))
        except (ValueError, InvalidSignature) as exc:
            raise ANOError("IDENTITY_SIGNATURE_INVALID", "external assertion signature is invalid") from exc
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        issued_at = parse_timestamp(assertion["issued_at"])
        expires_at = parse_timestamp(assertion["expires_at"])
        if expires_at <= issued_at or expires_at - issued_at > timedelta(seconds=900):
            raise ANOError("IDENTITY_LIFETIME_INVALID", "external assertion validity interval is invalid")
        if current + self.clock_skew < issued_at or current - self.clock_skew >= expires_at:
            raise ANOError("IDENTITY_ASSERTION_EXPIRED", "external assertion is outside its validity interval")
        connection = sqlite3.connect(self.path, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM consumed_identity_assertions WHERE expires_at < ?",
                (current.isoformat(timespec="milliseconds").replace("+00:00", "Z"),),
            )
            try:
                connection.execute(
                    """INSERT INTO consumed_identity_assertions
                       (issuer, assertion_id, subject, consumed_at, expires_at) VALUES (?, ?, ?, ?, ?)""",
                    (
                        assertion["issuer"], assertion["assertion_id"], assertion["subject"],
                        current.isoformat(timespec="milliseconds").replace("+00:00", "Z"),
                        assertion["expires_at"],
                    ),
                )
            except sqlite3.IntegrityError as exc:
                raise ANOError("IDENTITY_ASSERTION_REPLAY", "external assertion was already consumed") from exc
            session = self.boundary.open_session(assertion["subject"], now=current)
            connection.commit()
            return session
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

