from __future__ import annotations

import copy
import hashlib
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .errors import ANOError
from .evidence import IndependentClusterEvidenceVerifier
from .schema import SchemaCatalog
from .util import parse_timestamp, sha256_json


def witness_public_key_fingerprint(public_key: Ed25519PublicKey) -> str:
    """Return the policy fingerprint of an Ed25519 public key's raw bytes."""
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


class PolicyBoundClusterEvidenceVerifier:
    """Verify evidence against an explicit, historical witness-key lifecycle policy."""

    def __init__(
        self,
        catalog: SchemaCatalog,
        policy: dict[str, Any],
        trusted_public_keys: dict[str, Ed25519PublicKey],
        *,
        expected_policy_id: str,
        minimum_policy_version: int,
        expected_policy_hash: str,
        maximum_future_skew_seconds: int = 60,
    ) -> None:
        trusted_policy = copy.deepcopy(policy)
        catalog.validate("witness-trust-policy", trusted_policy)
        if trusted_policy["policy_id"] != expected_policy_id:
            raise ANOError("WITNESS_KEY_POLICY_IDENTITY", "witness policy identity does not match the configured trust root")
        if trusted_policy["policy_version"] < minimum_policy_version:
            raise ANOError("WITNESS_KEY_POLICY_ROLLBACK", "witness policy version is older than the configured floor")
        if sha256_json(trusted_policy) != expected_policy_hash:
            raise ANOError("WITNESS_KEY_POLICY_INTEGRITY", "witness policy does not match its configured integrity anchor")
        policy_issued_at = parse_timestamp(trusted_policy["issued_at"])
        entries: dict[str, dict[str, Any]] = {}
        for item in trusted_policy["keys"]:
            key_id = str(item["key_id"])
            if key_id in entries:
                raise ANOError("WITNESS_KEY_POLICY_INVALID", "witness policy contains a duplicate key identifier")
            valid_from = parse_timestamp(item["valid_from"])
            valid_until = parse_timestamp(item["valid_until"])
            if valid_from >= valid_until:
                raise ANOError("WITNESS_KEY_POLICY_INVALID", "witness key validity interval is empty or inverted")
            revoked_at = None if item["revoked_at"] is None else parse_timestamp(item["revoked_at"])
            if revoked_at is not None and not (valid_from <= revoked_at < valid_until):
                raise ANOError("WITNESS_KEY_POLICY_INVALID", "witness key revocation is outside its validity interval")
            if item["status"] == "active" and not (valid_from <= policy_issued_at < valid_until):
                raise ANOError("WITNESS_KEY_POLICY_INVALID", "active witness key is not valid when the policy was issued")
            if item["status"] == "retired" and valid_until > policy_issued_at:
                raise ANOError("WITNESS_KEY_POLICY_INVALID", "retired witness key has a future signing-validity end")
            if item["status"] == "revoked" and revoked_at is not None and revoked_at > policy_issued_at:
                raise ANOError("WITNESS_KEY_POLICY_INVALID", "witness key is marked revoked before its revocation time")
            public_key = trusted_public_keys.get(key_id)
            if public_key is None:
                raise ANOError("WITNESS_KEY_MISSING", "witness policy references an unavailable public key")
            if witness_public_key_fingerprint(public_key) != item["public_key_sha256"]:
                raise ANOError("WITNESS_KEY_FINGERPRINT_MISMATCH", "witness public key does not match its policy fingerprint")
            entries[key_id] = item
        unexpected = set(trusted_public_keys) - set(entries)
        if unexpected:
            raise ANOError("WITNESS_KEY_POLICY_INVALID", "trusted key set contains keys absent from the witness policy")
        self._catalog = catalog
        self._policy = trusted_policy
        self._entries = entries
        self._public_keys = dict(trusted_public_keys)
        self._future_skew = maximum_future_skew_seconds

    def verify(
        self,
        report: dict[str, Any],
        envelope: dict[str, Any],
        *,
        expected_sequence: int,
        expected_previous_envelope_hash: str | None,
    ) -> dict[str, Any]:
        self._catalog.validate("cluster-evidence-envelope", envelope)
        key_id = str(envelope["signatures"][0]["keyid"])
        policy_entry = self._entries.get(key_id)
        if policy_entry is None:
            raise ANOError("WITNESS_UNTRUSTED", "evidence witness key is absent from the trust policy")
        verifier = IndependentClusterEvidenceVerifier(
            self._catalog,
            {key_id: (policy_entry["witness_domain"], self._public_keys[key_id])},
            maximum_future_skew_seconds=self._future_skew,
        )
        statement = verifier.verify(
            report, envelope,
            expected_sequence=expected_sequence,
            expected_previous_envelope_hash=expected_previous_envelope_hash,
        )
        witnessed_at = parse_timestamp(statement["witnessed_at"])
        if not (parse_timestamp(policy_entry["valid_from"]) <= witnessed_at < parse_timestamp(policy_entry["valid_until"])):
            raise ANOError("WITNESS_KEY_OUTSIDE_VALIDITY", "evidence was signed outside the witness key validity interval")
        if policy_entry["status"] == "revoked":
            if policy_entry["revocation_mode"] == "retroactive":
                raise ANOError("WITNESS_KEY_REVOKED", "witness key is retroactively revoked")
            if witnessed_at >= parse_timestamp(policy_entry["revoked_at"]):
                raise ANOError("WITNESS_KEY_REVOKED", "evidence was signed after prospective key revocation")
        return statement
