from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .errors import ANOError
from .schema import SchemaCatalog
from .util import canonical_json, new_id, parse_timestamp, sha256_json


def _stamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _unb64url(value: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, TypeError) as exc:
        raise ANOError("TOKEN_ENCODING_INVALID", "token contains invalid base64url data") from exc


@runtime_checkable
class RemoteKmsProvider(Protocol):
    def capabilities(self) -> dict[str, Any]: ...
    def wrap_key(self, plaintext_key: bytes, context: dict[str, Any], *, purpose: str, caller: str) -> dict[str, Any]: ...
    def unwrap_key(self, envelope: dict[str, Any], context: dict[str, Any], *, purpose: str, caller: str) -> bytes: ...
    def rewrap_key(self, envelope: dict[str, Any], context: dict[str, Any], *, purpose: str, caller: str) -> tuple[dict[str, Any], dict[str, Any]]: ...


class ReferenceRemoteKmsProvider:
    """KMS-boundary contract emulator; proves policy semantics, not remote cloud/HSM deployment."""

    def __init__(
        self, catalog: SchemaCatalog, *, provider_id: str = "kms_external_reference",
        key_resource: str = "keys/ano/root", allowed_callers: dict[str, set[str]] | None = None,
    ) -> None:
        self.catalog = catalog
        self.provider_id = provider_id
        self.key_resource = key_resource
        self.allowed_callers = {key: set(value) for key, value in (allowed_callers or {}).items()}
        self._keys: dict[int, bytes] = {1: AESGCM.generate_key(bit_length=256)}
        self._active_version = 1

    def capabilities(self) -> dict[str, Any]:
        result = {
            "schema_version": "0.5.0", "provider": self.provider_id,
            "authenticated_wrap": True, "remote_rewrap": True, "purpose_binding": True,
            "non_exportable_master_key": True, "runtime_verified": True,
            "remote_transport_verified": False, "hsm_backed": False,
        }
        self.catalog.validate("kms-provider-capabilities", result)
        return result

    @property
    def active_version(self) -> int:
        return self._active_version

    def rotate(self) -> int:
        self._active_version += 1
        self._keys[self._active_version] = AESGCM.generate_key(bit_length=256)
        return self._active_version

    def _authorize(self, caller: str, purpose: str) -> None:
        if purpose not in self.allowed_callers.get(caller, set()):
            raise ANOError("KMS_CALLER_DENIED", "caller is not authorized for the requested key purpose")

    def _aad(self, context: dict[str, Any], purpose: str) -> bytes:
        return canonical_json({"provider": self.provider_id, "resource": self.key_resource, "purpose": purpose, "context": context}).encode()

    def wrap_key(
        self, plaintext_key: bytes, context: dict[str, Any], *, purpose: str, caller: str,
    ) -> dict[str, Any]:
        self._authorize(caller, purpose)
        if len(plaintext_key) != 32:
            raise ANOError("KMS_PLAINTEXT_KEY_INVALID", "only 256-bit data keys may be wrapped")
        nonce = os.urandom(12)
        version = self._active_version
        result = {
            "schema_version": "0.5.0", "provider": self.provider_id,
            "key_resource": self.key_resource, "key_version": version,
            "algorithm": "AES-256-GCM", "purpose": purpose,
            "context_hash": sha256_json(context), "request_id": new_id("kmr"),
            "nonce": base64.b64encode(nonce).decode(),
            "ciphertext": base64.b64encode(AESGCM(self._keys[version]).encrypt(nonce, plaintext_key, self._aad(context, purpose))).decode(),
        }
        self.catalog.validate("remote-wrapped-key", result)
        return result

    def unwrap_key(
        self, envelope: dict[str, Any], context: dict[str, Any], *, purpose: str, caller: str,
    ) -> bytes:
        self.catalog.validate("remote-wrapped-key", envelope)
        self._authorize(caller, purpose)
        if envelope["provider"] != self.provider_id or envelope["key_resource"] != self.key_resource:
            raise ANOError("KMS_KEY_IDENTITY_MISMATCH", "wrapped key belongs to another provider or resource")
        if envelope["purpose"] != purpose or envelope["context_hash"] != sha256_json(context):
            raise ANOError("KMS_BINDING_MISMATCH", "purpose or encryption context does not match the wrapped key")
        key = self._keys.get(int(envelope["key_version"]))
        if key is None:
            raise ANOError("KMS_KEY_UNAVAILABLE", "referenced master key version is unavailable")
        try:
            return AESGCM(key).decrypt(
                base64.b64decode(envelope["nonce"], validate=True),
                base64.b64decode(envelope["ciphertext"], validate=True), self._aad(context, purpose),
            )
        except (ValueError, InvalidTag) as exc:
            raise ANOError("KMS_UNWRAP_FAILED", "wrapped key authentication failed") from exc

    def rewrap_key(
        self, envelope: dict[str, Any], context: dict[str, Any], *, purpose: str, caller: str,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        plaintext = self.unwrap_key(envelope, context, purpose=purpose, caller=caller)
        replacement = self.wrap_key(plaintext, context, purpose=purpose, caller=caller)
        receipt = {
            "rewrap_id": new_id("krw"), "schema_version": "0.5.0", "provider": self.provider_id,
            "key_resource": self.key_resource, "old_key_version": envelope["key_version"],
            "new_key_version": replacement["key_version"], "purpose": purpose,
            "context_hash": sha256_json(context), "old_envelope_hash": sha256_json(envelope),
            "new_envelope_hash": sha256_json(replacement), "rewrapped_at": _stamp(datetime.now(timezone.utc)),
        }
        self.catalog.validate("kms-rewrap-receipt", receipt)
        return replacement, receipt


class EdDsaJwksIssuer:
    """Small deterministic-contract issuer for OIDC-like and JWT-SVID conformance tests."""

    def __init__(self, issuer: str, key_id: str = "identity_key_001") -> None:
        self.issuer, self.key_id = issuer, key_id
        self._keys: dict[str, Ed25519PrivateKey] = {key_id: Ed25519PrivateKey.generate()}

    def rotate(self, key_id: str) -> None:
        self.key_id = key_id
        self._keys[key_id] = Ed25519PrivateKey.generate()

    def jwks(self, *, include_retired: bool = True) -> dict[str, Any]:
        keys = self._keys.items() if include_retired else [(self.key_id, self._keys[self.key_id])]
        return {"keys": [{
            "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid,
            "x": _b64url(private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)),
        } for kid, private in keys]}

    def issue(
        self, subject: str, audience: str, *, now: datetime | None = None,
        lifetime_seconds: int = 300, selectors: dict[str, str] | None = None,
    ) -> str:
        if lifetime_seconds < 1 or lifetime_seconds > 900:
            raise ANOError("IDENTITY_LIFETIME_INVALID", "workload token lifetime must be between 1 and 900 seconds")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        header = {"alg": "EdDSA", "typ": "JWT", "kid": self.key_id}
        payload: dict[str, Any] = {
            "iss": self.issuer, "sub": subject, "aud": audience, "jti": new_id("wti"),
            "iat": int(current.timestamp()), "exp": int((current + timedelta(seconds=lifetime_seconds)).timestamp()),
        }
        if selectors is not None:
            payload["selectors"] = selectors
        signing_input = f"{_b64url(canonical_json(header).encode())}.{_b64url(canonical_json(payload).encode())}"
        signature = self._keys[self.key_id].sign(signing_input.encode())
        return f"{signing_input}.{_b64url(signature)}"


class SqliteIdentityReplayStore:
    """Atomically consume short-lived identity token IDs across verifier restarts."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS consumed_workload_tokens (issuer TEXT NOT NULL, token_id TEXT NOT NULL, expires_at INTEGER NOT NULL, PRIMARY KEY(issuer, token_id))"
            )
            connection.commit()
        finally:
            connection.close()

    def consume(self, issuer: str, token_id: str, expires_at: int, current: int) -> None:
        connection = sqlite3.connect(self.path, isolation_level=None)
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM consumed_workload_tokens WHERE expires_at <= ?", (current,))
            try:
                connection.execute(
                    "INSERT INTO consumed_workload_tokens(issuer,token_id,expires_at) VALUES(?,?,?)",
                    (issuer, token_id, expires_at),
                )
            except sqlite3.IntegrityError as exc:
                raise ANOError("IDENTITY_TOKEN_REPLAY", "workload identity token was already consumed") from exc
            connection.commit()
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class WorkloadIdentityVerifier:
    """Fail-closed EdDSA JWKS verifier with OIDC/SPIFFE profiles and explicit key refresh."""

    def __init__(
        self, catalog: SchemaCatalog, *, issuer: str, audience: str, jwks: dict[str, Any],
        mode: str = "oidc", trust_domain: str | None = None, max_lifetime_seconds: int = 900,
        replay_path: str | Path | None = None, verifier_key_id: str = "identity_verifier_001",
        verifier_private_key: Ed25519PrivateKey | None = None,
    ) -> None:
        if mode not in {"oidc", "spiffe"}:
            raise ANOError("IDENTITY_MODE_INVALID", "identity mode must be oidc or spiffe")
        self.catalog, self.issuer, self.audience, self.mode = catalog, issuer, audience, mode
        self.trust_domain, self.max_lifetime = trust_domain, max_lifetime_seconds
        self._consumed: set[str] = set()
        self._replay_store = SqliteIdentityReplayStore(replay_path) if replay_path is not None else None
        self.verifier_key_id = verifier_key_id
        self._verifier_private_key = verifier_private_key or Ed25519PrivateKey.generate()
        self.refresh(jwks)

    @property
    def verifier_public_key(self) -> Ed25519PublicKey:
        return self._verifier_private_key.public_key()

    def refresh(self, jwks: dict[str, Any]) -> None:
        parsed: dict[str, Ed25519PublicKey] = {}
        for item in jwks.get("keys", []):
            if item.get("kty") != "OKP" or item.get("crv") != "Ed25519" or item.get("alg") != "EdDSA" or item.get("use") != "sig":
                continue
            try:
                parsed[item["kid"]] = Ed25519PublicKey.from_public_bytes(_unb64url(item["x"]))
            except (KeyError, ValueError):
                continue
        if not parsed:
            raise ANOError("JWKS_EMPTY", "JWKS contains no acceptable Ed25519 signing key")
        self._keys = parsed

    def verify(self, token: str, *, now: datetime | None = None, consume: bool = True) -> dict[str, Any]:
        parts = token.split(".")
        if len(parts) != 3:
            raise ANOError("IDENTITY_TOKEN_INVALID", "identity token is not compact JWT")
        try:
            header = json.loads(_unb64url(parts[0]))
            claims = json.loads(_unb64url(parts[1]))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ANOError("IDENTITY_TOKEN_INVALID", "identity token JSON is invalid") from exc
        if header.get("alg") != "EdDSA" or header.get("typ") != "JWT":
            raise ANOError("IDENTITY_ALGORITHM_DENIED", "only EdDSA JWT identity tokens are accepted")
        key = self._keys.get(str(header.get("kid", "")))
        if key is None:
            raise ANOError("IDENTITY_KEY_UNTRUSTED", "token key is absent from the current JWKS")
        try:
            key.verify(_unb64url(parts[2]), f"{parts[0]}.{parts[1]}".encode())
        except (InvalidSignature, ValueError) as exc:
            raise ANOError("IDENTITY_SIGNATURE_INVALID", "workload identity signature is invalid") from exc
        required = {"iss", "sub", "aud", "jti", "iat", "exp"}
        if not required.issubset(claims) or claims["iss"] != self.issuer or claims["aud"] != self.audience:
            raise ANOError("IDENTITY_CLAIMS_INVALID", "issuer, audience, or required claims are invalid")
        current = int((now or datetime.now(timezone.utc)).timestamp())
        try:
            issued, expires = int(claims["iat"]), int(claims["exp"])
        except (TypeError, ValueError) as exc:
            raise ANOError("IDENTITY_CLAIMS_INVALID", "identity token timestamps are invalid") from exc
        if expires <= issued or expires - issued > self.max_lifetime or current < issued - 30 or current >= expires:
            raise ANOError("IDENTITY_TOKEN_EXPIRED", "identity token is outside its bounded validity interval")
        if self.mode == "spiffe":
            prefix = f"spiffe://{self.trust_domain}/"
            if not self.trust_domain or not str(claims["sub"]).startswith(prefix):
                raise ANOError("SPIFFE_TRUST_DOMAIN_MISMATCH", "SVID subject is outside the configured trust domain")
        if consume:
            if self._replay_store is not None:
                self._replay_store.consume(claims["iss"], claims["jti"], expires, current)
            else:
                if claims["jti"] in self._consumed:
                    raise ANOError("IDENTITY_TOKEN_REPLAY", "workload identity token was already consumed")
                self._consumed.add(claims["jti"])
        body = {
            "identity_id": new_id("wid"), "schema_version": "0.5.0", "mode": self.mode,
            "issuer": claims["iss"], "subject": claims["sub"], "audience": claims["aud"],
            "token_id": claims["jti"], "key_id": header["kid"],
            "selectors": claims.get("selectors", {}), "issued_at": _stamp(datetime.fromtimestamp(issued, timezone.utc)),
            "expires_at": _stamp(datetime.fromtimestamp(expires, timezone.utc)),
            "verifier_key_id": self.verifier_key_id,
        }
        identity = {
            **body,
            "verification_proof": base64.b64encode(
                self._verifier_private_key.sign(canonical_json(body).encode())
            ).decode(),
        }
        self.catalog.validate("workload-identity", identity)
        return identity

    def verify_identity(self, identity: dict[str, Any], *, now: datetime | None = None) -> None:
        self.catalog.validate("workload-identity", identity)
        if identity["verifier_key_id"] != self.verifier_key_id:
            raise ANOError("IDENTITY_PROOF_UNTRUSTED", "identity proof was issued by another verifier")
        body = copy.deepcopy(identity)
        proof = body.pop("verification_proof")
        try:
            self.verifier_public_key.verify(base64.b64decode(proof, validate=True), canonical_json(body).encode())
        except (ValueError, InvalidSignature) as exc:
            raise ANOError("IDENTITY_PROOF_INVALID", "verified identity object was modified or forged") from exc
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if parse_timestamp(identity["expires_at"]) <= current:
            raise ANOError("IDENTITY_TOKEN_EXPIRED", "verified identity has expired")


class SqliteSecretLeaseBroker:
    """Encrypted-at-rest reference broker with subject/audience/purpose-bound short leases."""

    def __init__(
        self, path: str | Path, catalog: SchemaCatalog, broker_key: bytes,
        identity_verifier: WorkloadIdentityVerifier,
    ) -> None:
        if len(broker_key) != 32:
            raise ANOError("SECRET_BROKER_KEY_INVALID", "secret broker key must be 256 bits")
        self.path, self.catalog, self._key = Path(path), catalog, broker_key
        self.identity_verifier = identity_verifier
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(self.path)
        try:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS secrets (
                    secret_id TEXT PRIMARY KEY, purpose TEXT NOT NULL,
                    allowed_subjects_json TEXT NOT NULL, allowed_audiences_json TEXT NOT NULL,
                    nonce TEXT NOT NULL, ciphertext TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS secret_leases (
                    lease_id TEXT PRIMARY KEY, token_hash TEXT UNIQUE NOT NULL, secret_id TEXT NOT NULL,
                    subject TEXT NOT NULL, audience TEXT NOT NULL, purpose TEXT NOT NULL,
                    issued_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL,
                    redemptions INTEGER NOT NULL DEFAULT 0, max_redemptions INTEGER NOT NULL,
                    FOREIGN KEY(secret_id) REFERENCES secrets(secret_id));
                CREATE TABLE IF NOT EXISTS secret_events (
                    event_id TEXT PRIMARY KEY, lease_id TEXT NOT NULL, event_type TEXT NOT NULL,
                    detected_at TEXT NOT NULL, token_hash TEXT NOT NULL);
            """)
            connection.commit()
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def put_secret(
        self, secret_id: str, purpose: str, material: bytes, *,
        allowed_subjects: set[str], allowed_audiences: set[str],
    ) -> None:
        if not material or not allowed_subjects or not allowed_audiences:
            raise ANOError("SECRET_POLICY_INVALID", "secret material and subject/audience ACLs are required")
        nonce = os.urandom(12)
        ciphertext = AESGCM(self._key).encrypt(nonce, material, f"{secret_id}:{purpose}".encode())
        connection = self._connect()
        try:
            connection.execute(
                "INSERT OR REPLACE INTO secrets(secret_id,purpose,allowed_subjects_json,allowed_audiences_json,nonce,ciphertext) VALUES(?,?,?,?,?,?)",
                (secret_id, purpose, canonical_json(sorted(allowed_subjects)), canonical_json(sorted(allowed_audiences)),
                 base64.b64encode(nonce).decode(), base64.b64encode(ciphertext).decode()),
            )
        finally:
            connection.close()

    def issue(
        self, identity: dict[str, Any], secret_id: str, *, purpose: str, audience: str,
        now: datetime | None = None, lifetime_seconds: int = 60, max_redemptions: int = 1,
    ) -> dict[str, Any]:
        self.catalog.validate("workload-identity", identity)
        if lifetime_seconds < 1 or lifetime_seconds > 300 or max_redemptions < 1 or max_redemptions > 10:
            raise ANOError("SECRET_LEASE_LIMIT_INVALID", "lease lifetime or redemption limit exceeds policy")
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        self.identity_verifier.verify_identity(identity, now=current)
        if parse_timestamp(identity["expires_at"]) <= current or identity["audience"] != audience:
            raise ANOError("SECRET_IDENTITY_INVALID", "identity is expired or audience does not match")
        connection = self._connect()
        try:
            row = connection.execute(
                "SELECT purpose,allowed_subjects_json,allowed_audiences_json FROM secrets WHERE secret_id = ?",
                (secret_id,),
            ).fetchone()
            if row is None or row["purpose"] != purpose:
                raise ANOError("SECRET_PURPOSE_DENIED", "secret is absent or bound to another purpose")
            if identity["subject"] not in json.loads(row["allowed_subjects_json"]) or audience not in json.loads(row["allowed_audiences_json"]):
                raise ANOError("SECRET_ACCESS_DENIED", "workload subject or audience is outside the secret ACL")
            lease_id, token = new_id("sls"), _b64url(os.urandom(32))
            expires = min(current + timedelta(seconds=lifetime_seconds), parse_timestamp(identity["expires_at"]))
            lease = {
                "lease_id": lease_id, "schema_version": "0.5.0", "secret_id": secret_id,
                "subject": identity["subject"], "audience": audience, "purpose": purpose,
                "issued_at": _stamp(current), "expires_at": _stamp(expires), "max_redemptions": max_redemptions,
                "lease_token": token,
            }
            self.catalog.validate("secret-lease", lease)
            connection.execute(
                "INSERT INTO secret_leases VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (lease_id, hashlib.sha256(token.encode()).hexdigest(), secret_id, identity["subject"], audience,
                 purpose, lease["issued_at"], lease["expires_at"], "active", 0, max_redemptions),
            )
            return lease
        finally:
            connection.close()

    def redeem(
        self, lease: dict[str, Any], identity: dict[str, Any], *, purpose: str, audience: str,
        now: datetime | None = None,
    ) -> bytes:
        self.catalog.validate("secret-lease", lease)
        self.catalog.validate("workload-identity", identity)
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        self.identity_verifier.verify_identity(identity, now=current)
        token_hash = hashlib.sha256(lease["lease_token"].encode()).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT * FROM secret_leases WHERE lease_id = ?", (lease["lease_id"],)).fetchone()
            if row is None or row["token_hash"] != token_hash:
                raise ANOError("SECRET_LEASE_INVALID", "secret lease token is invalid")
            if row["status"] != "active" or parse_timestamp(row["expires_at"]) <= current:
                raise ANOError("SECRET_LEASE_INACTIVE", "secret lease is expired, revoked, or leaked")
            if row["subject"] != identity["subject"] or row["audience"] != audience or row["purpose"] != purpose:
                raise ANOError("SECRET_LEASE_BINDING_MISMATCH", "secret lease subject, audience, or purpose changed")
            if parse_timestamp(identity["expires_at"]) <= current:
                raise ANOError("SECRET_IDENTITY_INVALID", "redeeming identity has expired")
            if int(row["redemptions"]) >= int(row["max_redemptions"]):
                raise ANOError("SECRET_LEASE_EXHAUSTED", "secret lease redemption limit was reached")
            secret = connection.execute("SELECT * FROM secrets WHERE secret_id = ?", (row["secret_id"],)).fetchone()
            material = AESGCM(self._key).decrypt(
                base64.b64decode(secret["nonce"]), base64.b64decode(secret["ciphertext"]),
                f"{row['secret_id']}:{row['purpose']}".encode(),
            )
            connection.execute("UPDATE secret_leases SET redemptions = redemptions + 1 WHERE lease_id = ?", (row["lease_id"],))
            connection.commit()
            return material
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()

    def revoke(self, lease_id: str) -> None:
        connection = self._connect()
        try:
            updated = connection.execute("UPDATE secret_leases SET status='revoked' WHERE lease_id=? AND status='active'", (lease_id,)).rowcount
            if updated != 1:
                raise ANOError("SECRET_LEASE_INACTIVE", "only an active secret lease can be revoked")
        finally:
            connection.close()

    def report_leak(self, lease_token: str, *, now: datetime | None = None) -> dict[str, Any]:
        token_hash = hashlib.sha256(lease_token.encode()).hexdigest()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT lease_id FROM secret_leases WHERE token_hash = ?", (token_hash,)).fetchone()
            if row is None:
                raise ANOError("SECRET_LEAK_TOKEN_UNKNOWN", "leaked token is not known to this broker")
            connection.execute("UPDATE secret_leases SET status='leaked' WHERE lease_id=?", (row["lease_id"],))
            event = {
                "event_id": new_id("sle"), "schema_version": "0.5.0", "lease_id": row["lease_id"],
                "event_type": "credential_leak", "detected_at": _stamp(now or datetime.now(timezone.utc)),
                "token_fingerprint": f"sha256:{token_hash}", "lease_revoked": True,
            }
            self.catalog.validate("secret-security-event", event)
            connection.execute(
                "INSERT INTO secret_events VALUES(?,?,?,?,?)",
                (event["event_id"], event["lease_id"], event["event_type"], event["detected_at"], token_hash),
            )
            connection.commit()
            return event
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


class ArtifactProvenanceSigner:
    def __init__(self, catalog: SchemaCatalog, builder_id: str, key_id: str, private_key: Ed25519PrivateKey | None = None) -> None:
        self.catalog, self.builder_id, self.key_id = catalog, builder_id, key_id
        self.private_key = private_key or Ed25519PrivateKey.generate()

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    def attest(
        self, artifact_hash: str, sbom: dict[str, Any], *, source_uri: str, source_commit: str,
        materials: list[str], invocation: dict[str, Any], isolated: bool, reproducible: bool,
        now: datetime | None = None,
    ) -> dict[str, Any]:
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        body = {
            "attestation_id": new_id("att"), "schema_version": "0.5.0", "artifact_hash": artifact_hash,
            "sbom_hash": sha256_json(sbom), "source_uri": source_uri, "source_commit": source_commit,
            "materials": materials, "invocation_hash": sha256_json(invocation), "builder_id": self.builder_id,
            "isolated_build": isolated, "reproducible": reproducible, "key_id": self.key_id,
            "issued_at": _stamp(current), "expires_at": _stamp(current + timedelta(hours=1)),
        }
        result = {**body, "signature": base64.b64encode(self.private_key.sign(canonical_json(body).encode())).decode()}
        self.catalog.validate("artifact-provenance-attestation", result)
        return result


class SupplyChainPolicyVerifier:
    def __init__(
        self, catalog: SchemaCatalog, trusted_builders: dict[str, tuple[str, Ed25519PublicKey]], *,
        allowed_source_prefixes: tuple[str, ...], require_isolated: bool = True, require_reproducible: bool = True,
    ) -> None:
        self.catalog, self.trusted_builders = catalog, dict(trusted_builders)
        self.allowed_sources = allowed_source_prefixes
        self.require_isolated, self.require_reproducible = require_isolated, require_reproducible

    def verify(
        self, attestation: dict[str, Any], *, artifact_hash: str, sbom: dict[str, Any],
        now: datetime | None = None,
    ) -> dict[str, Any]:
        self.catalog.validate("artifact-provenance-attestation", attestation)
        trusted = self.trusted_builders.get(attestation["builder_id"])
        if trusted is None or trusted[0] != attestation["key_id"]:
            raise ANOError("SUPPLY_CHAIN_BUILDER_UNTRUSTED", "builder or signing key is not trusted")
        body = copy.deepcopy(attestation)
        signature_text = body.pop("signature")
        try:
            trusted[1].verify(base64.b64decode(signature_text, validate=True), canonical_json(body).encode())
        except (ValueError, InvalidSignature) as exc:
            raise ANOError("SUPPLY_CHAIN_SIGNATURE_INVALID", "provenance signature is invalid") from exc
        current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
        if parse_timestamp(attestation["issued_at"]) > current or parse_timestamp(attestation["expires_at"]) <= current:
            raise ANOError("SUPPLY_CHAIN_ATTESTATION_EXPIRED", "provenance attestation is outside its validity interval")
        if attestation["artifact_hash"] != artifact_hash or attestation["sbom_hash"] != sha256_json(sbom):
            raise ANOError("SUPPLY_CHAIN_BINDING_MISMATCH", "artifact or SBOM does not match signed provenance")
        if not any(attestation["source_uri"].startswith(prefix) for prefix in self.allowed_sources):
            raise ANOError("SUPPLY_CHAIN_SOURCE_DENIED", "source repository is outside policy")
        if re.fullmatch(r"[0-9a-f]{40,64}", attestation["source_commit"]) is None:
            raise ANOError("SUPPLY_CHAIN_SOURCE_MUTABLE", "source revision must be an immutable commit digest")
        if not attestation["materials"] or len(set(attestation["materials"])) != len(attestation["materials"]):
            raise ANOError("SUPPLY_CHAIN_MATERIALS_INVALID", "build materials must be non-empty and unique")
        if self.require_isolated and not attestation["isolated_build"]:
            raise ANOError("SUPPLY_CHAIN_ISOLATION_REQUIRED", "policy requires an isolated builder")
        if self.require_reproducible and not attestation["reproducible"]:
            raise ANOError("SUPPLY_CHAIN_REPRODUCIBILITY_REQUIRED", "policy requires a reproducible build")
        decision = {
            "decision_id": new_id("scd"), "schema_version": "0.5.0", "status": "trusted",
            "artifact_hash": artifact_hash, "attestation_id": attestation["attestation_id"],
            "attestation_hash": sha256_json(attestation), "sbom_hash": sha256_json(sbom),
            "builder_id": attestation["builder_id"], "verified_at": _stamp(current),
        }
        self.catalog.validate("artifact-trust-decision", decision)
        return decision
