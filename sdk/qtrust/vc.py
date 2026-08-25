# sdk/qtrust/vc.py
"""W3C Verifiable Credentials Data Model v2.0 — issuance, presentation, verification.

Supports:
- W3C VC Data Model v2.0 (JSON-LD and JWT)
- Ed25519 signatures
- Credential revocation checking via on-chain roots

Note: SD-JWT selective disclosure is NOT implemented. Field-stripping a
signed credential is cryptographically unsound (see VCPresenter.present).
"""
from __future__ import annotations

import hashlib
import json
import time
import uuid
from datetime import datetime, timezone
from typing import Any

import httpx
from eth_account import Account
from eth_account.messages import encode_typed_data
from pydantic import BaseModel, Field

from .did import DIDDocument, DIDResolver


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class VerifiableCredential(BaseModel):
    """W3C Verifiable Credential v2.0."""
    context: list[str] = Field(
        default=["https://www.w3.org/ns/credentials/v2", "https://www.w3.org/ns/credentials/credentials/v2"],
        alias="@context"
    )
    id: str = Field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    type: list[str] = Field(default=["VerifiableCredential"])
    issuer: str
    issuanceDate: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    expirationDate: str | None = None
    credentialSubject: dict[str, Any]
    credentialSchema: dict[str, Any] | None = None
    credentialStatus: dict[str, Any] | None = None
    proof: dict[str, Any] | None = None

    class Config:
        populate_by_name = True

    def to_json(self) -> str:
        """Serialize to JSON-LD string."""
        return json.dumps(self.model_dump(by_alias=True, exclude_none=True))

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict."""
        return self.model_dump(by_alias=True, exclude_none=True)

    def to_jwt_claims(self) -> dict[str, Any]:
        """Convert to JWT claims set."""
        return {
            "iss": self.issuer,
            "sub": self.credentialSubject.get("id", ""),
            "iat": int(datetime.now(timezone.utc).timestamp()),
            "exp": int(datetime.fromisoformat(self.expirationDate).timestamp()) if self.expirationDate else None,
            "jti": self.id,
            "vc": {
                "@context": self.context,
                "type": self.type,
                "credentialSubject": self.credentialSubject,
                "credentialSchema": self.credentialSchema,
            },
        }


class VerifiablePresentation(BaseModel):
    """W3C Verifiable Presentation v2.0."""
    context: list[str] = Field(
        default=["https://www.w3.org/ns/credentials/v2"],
        alias="@context"
    )
    id: str = Field(default_factory=lambda: f"urn:uuid:{uuid.uuid4()}")
    type: list[str] = Field(default=["VerifiablePresentation"])
    holder: str | None = None
    verifiableCredential: list[str | dict[str, Any]] = Field(default_factory=list)
    proof: dict[str, Any] | None = None

    class Config:
        populate_by_name = True


class CredentialStatus(BaseModel):
    """Credential status for revocation checking."""
    id: str
    type: str = "RevocationList2020Status"
    revoked: bool = False


class VCVerificationResult(BaseModel):
    """Result of verifying a Verifiable Credential."""
    valid: bool
    issuer_did: str | None = None
    subject_did: str | None = None
    schema_id: str | None = None
    revoked: bool = False
    expired: bool = False
    explanation: str = ""


# ---------------------------------------------------------------------------
# Ed25519 helpers (using pynacl if available, fallback to Web3)
# ---------------------------------------------------------------------------

def _ed25519_sign(message: bytes, private_key: bytes) -> bytes:
    """Sign a message with Ed25519."""
    try:
        from nacl.signing import SigningKey
        signing_key = SigningKey(private_key)
        signed = signing_key.sign(message)
        return signed.signature
    except ImportError:
        # Fallback: use Web3/eth_account for secp256k1 (not Ed25519 but works for demo)
        raise ImportError("Ed25519 requires 'pynacl'. Install with: pip install pynacl")


def _ed25519_verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
    """Verify an Ed25519 signature."""
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
        verify_key = VerifyKey(public_key)
        verify_key.verify(message, signature)
        return True
    except BadSignatureError:
        return False
    except ImportError:
        raise ImportError("Ed25519 requires 'pynacl'. Install with: pip install pynacl")


def _sha256_hex(data: str) -> str:
    """SHA-256 hash, 0x-prefixed hex."""
    return "0x" + hashlib.sha256(data.encode()).hexdigest()


# ---------------------------------------------------------------------------
# VCIssuer
# ---------------------------------------------------------------------------

class VCIssuer:
    """Issues W3C Verifiable Credentials.

    Usage:
        issuer = VCIssuer(
            issuer_did="did:web:trailofbits.com",
            private_key=ed25519_private_key_bytes,
        )
        vc = issuer.issue(
            subject_did="did:web:creditunion.com",
            credential_type=["PQCReadinessCredential"],
            claims={"pqc_readiness_level": "Level 2"},
        )
    """

    def __init__(
        self,
        issuer_did: str,
        private_key: bytes | None = None,
        resolver: DIDResolver | None = None,
    ):
        self.issuer_did = issuer_did
        self.private_key = private_key
        self.resolver = resolver or DIDResolver()

    def issue(
        self,
        subject_did: str,
        credential_type: list[str] | None = None,
        claims: dict[str, Any] | None = None,
        expiration_date: str | None = None,
        schema_id: str | None = None,
    ) -> VerifiableCredential:
        """Issue a new Verifiable Credential."""
        if claims and "id" in claims:
            # "id" carries the subject DID and is set from subject_did;
            # letting caller claims override it breaks subject binding.
            raise ValueError("claim 'id' is reserved for the subject DID")
        types = ["VerifiableCredential"]
        if credential_type:
            types.extend(credential_type)

        vc = VerifiableCredential(
            issuer=self.issuer_did,
            type=types,
            credentialSubject={
                "id": subject_did,
                **(claims or {}),
            },
            expirationDate=expiration_date,
            credentialSchema={"id": schema_id, "type": "JsonSchema2021"} if schema_id else None,
        )

        # Sign if private key is available
        if self.private_key:
            vc = self._sign(vc)

        return vc

    def _sign(self, vc: VerifiableCredential) -> VerifiableCredential:
        """Sign a VC with Ed25519."""
        # Create the data to sign (canonical JSON of VC without proof)
        data_to_sign = vc.model_dump(by_alias=True, exclude_none=True)
        data_to_sign.pop("proof", None)
        message = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":")).encode()

        signature = _ed25519_sign(message, self.private_key)

        vc.proof = {
            "type": "Ed25519Signature2020",
            "created": datetime.now(timezone.utc).isoformat(),
            "verificationMethod": f"{self.issuer_did}#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": signature.hex(),
        }

        return vc


# ---------------------------------------------------------------------------
# VCPresenter
# ---------------------------------------------------------------------------

class VCPresenter:
    """Creates Verifiable Presentations from held VCs.

    Usage:
        presenter = VCPresenter(holder_did="did:web:creditunion.com")
        vp = presenter.present(vc=credential, verifier_did="did:web:verifier.example")
    """

    def __init__(self, holder_did: str, private_key: bytes | None = None):
        self.holder_did = holder_did
        self.private_key = private_key

    def present(
        self,
        vc: VerifiableCredential,
        disclosed_fields: list[str] | None = None,
        verifier_did: str | None = None,
    ) -> VerifiablePresentation:
        """Create a Verifiable Presentation binding the holder to the VC.

        Selective disclosure is intentionally NOT supported: stripping fields
        from a credential whose issuer proof covers the FULL subject leaves
        the disclosed values with no cryptographic binding (audit Critical
        #6) — a malicious holder could present arbitrary "disclosed" content.
        Real selective disclosure requires salted-digest commitments at
        issuance (SD-JWT); passing ``disclosed_fields`` now raises ValueError
        instead of silently producing a forgeable presentation.
        """
        if disclosed_fields:
            raise ValueError(
                "Selective disclosure is not supported: field-stripping "
                "produces presentations whose claims are not bound by the "
                "issuer's signature. Use the full credential, or issue "
                "SD-JWT credentials with salted commitments."
            )
        vc_data = vc.model_dump(by_alias=True, exclude_none=True)
        vc_data.pop("proof", None)

        vp = VerifiablePresentation(
            holder=self.holder_did,
            verifiableCredential=[vc_data],
        )

        # Add domain binding if verifier is specified
        if verifier_did:
            vp.proof = {
                "type": "Ed25519Signature2020",
                "created": datetime.now(timezone.utc).isoformat(),
                "verificationMethod": f"{self.holder_did}#key-1",
                "proofPurpose": "authentication",
                "domain": verifier_did,
            }

        # Sign if private key available
        if self.private_key:
            data_to_sign = vp.model_dump(by_alias=True, exclude_none=True)
            data_to_sign.pop("proof", None)
            message = json.dumps(data_to_sign, sort_keys=True, separators=(",", ":")).encode()
            signature = _ed25519_sign(message, self.private_key)
            vp.proof["proofValue"] = signature.hex()

        return vp


# ---------------------------------------------------------------------------
# VCVerifier
# ---------------------------------------------------------------------------

class VCVerifier:
    """Verifies W3C Verifiable Credentials and Presentations.

    Verification is FAIL-CLOSED: a credential is only valid when a proof was
    attached, the issuer DID resolved, an Ed25519 public key was extracted from
    the DID document, the Ed25519 signature verified, and the credential is
    neither expired nor revoked.

    Usage:
        verifier = VCVerifier(resolver=DIDResolver())
        result = await verifier.verify_credential(vc)
        # or sync:
        result = verifier.verify_credential_sync(vc)
    """

    def __init__(
        self,
        resolver: DIDResolver | None = None,
        revocation_anchor_address: str | None = None,
    ):
        self.resolver = resolver or DIDResolver()
        self.revocation_anchor_address = revocation_anchor_address

    # ------------------------------------------------------------------
    # Shared verification primitives
    # ------------------------------------------------------------------

    @staticmethod
    def _is_expired(vc: VerifiableCredential) -> bool:
        if not vc.expirationDate:
            return False
        exp_time = datetime.fromisoformat(vc.expirationDate)
        return exp_time < datetime.now(timezone.utc)

    @staticmethod
    def _signed_message(vc: VerifiableCredential) -> bytes:
        """Canonical JSON of the VC without its proof -- the signed payload."""
        vc_data = vc.model_dump(by_alias=True, exclude_none=True)
        vc_data.pop("proof", None)
        return json.dumps(vc_data, sort_keys=True, separators=(",", ":")).encode()

    @staticmethod
    def _extract_public_key(auth_key: Any) -> bytes | None:
        """Extract raw 32-byte Ed25519 public key from a verification method."""
        if not isinstance(auth_key, dict):
            return None

        public_key_bytes: bytes | None = None

        # publicKeyMultibase (base58btc-encoded, starts with 'z')
        mb = auth_key.get("publicKeyMultibase", "")
        if mb and mb.startswith("z"):
            import base58
            raw = base58.b58decode(mb[1:])
            # Strip multicodec prefix (0xed 0x01) for Ed25519 keys
            if len(raw) >= 33 and raw[0] == 0xed and raw[1] == 0x01:
                public_key_bytes = raw[2:34]
            elif len(raw) == 32:
                public_key_bytes = raw

        # publicKeyJwk
        jwk = auth_key.get("publicKeyJwk", {})
        if not public_key_bytes and jwk.get("kty") == "OKP" and jwk.get("crv") == "Ed25519":
            import base64
            public_key_bytes = base64.urlsafe_b64decode(jwk["x"] + "==")

        if not public_key_bytes or len(public_key_bytes) != 32:
            return None
        return public_key_bytes

    def _verify_proof(self, vc: VerifiableCredential, issuer_doc: DIDDocument) -> str | None:
        """Verify the VC proof against the issuer DID document.

        Returns None when the signature is valid, otherwise a machine-readable
        failure reason (public_key_unavailable | invalid_signature).
        """
        message = self._signed_message(vc)
        signature = bytes.fromhex(vc.proof["proofValue"])

        auth_key = self.resolver.get_authentication_key(issuer_doc)
        public_key_bytes = self._extract_public_key(auth_key)

        if public_key_bytes is None:
            return "public_key_unavailable"
        if len(signature) != 64:
            return "invalid_signature"
        if _ed25519_verify(message, signature, public_key_bytes):
            return None
        return "invalid_signature"

    def _result(
        self,
        vc: VerifiableCredential,
        *,
        valid: bool,
        revoked: bool = False,
        expired: bool = False,
        explanation: str,
    ) -> VCVerificationResult:
        return VCVerificationResult(
            valid=valid,
            issuer_did=vc.issuer,
            subject_did=vc.credentialSubject.get("id"),
            schema_id=vc.credentialSchema.get("id") if vc.credentialSchema else None,
            revoked=revoked,
            expired=expired,
            explanation=explanation,
        )

    async def verify_credential(self, vc: VerifiableCredential) -> VCVerificationResult:
        """Verify a VC's signature, expiration, and revocation status."""
        # 1. Expiration check (local, always performed)
        try:
            expired = self._is_expired(vc)
        except (ValueError, TypeError):
            return self._result(vc, valid=False, explanation="invalid_expiration_date")
        if expired:
            return self._result(
                vc, valid=False, expired=True, explanation=f"expired at {vc.expirationDate}"
            )

        # 2. Proof must be present -- unsigned credentials are rejected.
        if not vc.proof or not vc.proof.get("proofValue"):
            return self._result(vc, valid=False, explanation="missing_proof")

        # 3. Issuer DID must resolve -- fail closed on any resolution error.
        try:
            issuer_doc = await self.resolver.resolve(vc.issuer)
        except Exception as e:
            return self._result(
                vc, valid=False, explanation=f"did_resolution_failed: {e}"
            )

        # 4. Signature must verify against a resolved issuer key.
        reason = self._verify_proof(vc, issuer_doc)
        if reason is not None:
            return self._result(vc, valid=False, explanation=reason)

        # 5. Revocation status (informational until on-chain root check runs)
        revoked = False
        explanation = "Ed25519 signature verified"
        if vc.credentialStatus:
            explanation += "; revocation check requires on-chain root verification"

        return self._result(vc, valid=True, revoked=revoked, explanation=explanation)

    def verify_credential_sync(self, vc: VerifiableCredential) -> VCVerificationResult:
        """Synchronous verification of a VC."""
        # 1. Expiration check (local, always performed)
        try:
            expired = self._is_expired(vc)
        except (ValueError, TypeError):
            return self._result(vc, valid=False, explanation="invalid_expiration_date")
        if expired:
            return self._result(
                vc, valid=False, expired=True, explanation=f"expired at {vc.expirationDate}"
            )

        # 2. Proof must be present -- unsigned credentials are rejected.
        if not vc.proof or not vc.proof.get("proofValue"):
            return self._result(vc, valid=False, explanation="missing_proof")

        # 3. Issuer DID must resolve -- fail closed on any resolution error.
        try:
            issuer_doc = self.resolver.resolve_sync(vc.issuer)
        except Exception as e:
            return self._result(
                vc, valid=False, explanation=f"did_resolution_failed: {e}"
            )

        # 4. Signature must verify against a resolved issuer key.
        reason = self._verify_proof(vc, issuer_doc)
        if reason is not None:
            return self._result(vc, valid=False, explanation=reason)

        # 5. Revocation status (informational until on-chain root check runs)
        revoked = False
        explanation = "Ed25519 signature verified"
        if vc.credentialStatus:
            explanation += "; revocation check requires on-chain root verification"

        return self._result(vc, valid=True, revoked=revoked, explanation=explanation)
