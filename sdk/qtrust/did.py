# sdk/qtrust/did.py
"""W3C DID:web resolver and DID document handling."""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from pydantic import BaseModel, Field

ALLOWED_HOSTS_ENV_VAR = "QTRUST_DID_ALLOWED_HOSTS"


class DIDDocument(BaseModel):
    """W3C DID Document."""
    id: str
    controller: str | None = None
    verificationMethod: list[dict[str, Any]] = Field(default_factory=list)
    authentication: list[str | dict[str, Any]] = Field(default_factory=list)
    assertionMethod: list[str | dict[str, Any]] = Field(default_factory=list)
    capabilityDelegation: list[str | dict[str, Any]] = Field(default_factory=list)
    capabilityInvocation: list[str | dict[str, Any]] = Field(default_factory=list)
    service: list[dict[str, Any]] = Field(default_factory=list)


class DIDResolver:
    """Resolves did:web and did:key DIDs.

    Usage:
        resolver = DIDResolver()
        doc = await resolver.resolve("did:web:example.com")
        # or sync:
        doc = resolver.resolve_sync("did:web:example.com")
    """

    def __init__(
        self,
        timeout: float = 10.0,
        allowed_hosts: list[str] | None = None,
        validate_resolution: bool = True,
    ):
        self.timeout = timeout
        self._cache: dict[str, tuple[DIDDocument, float]] = {}
        self._cache_ttl = 300  # 5 minutes
        # SSRF guard: explicit allowlist (param takes precedence over env var).
        self.allowed_hosts = set(allowed_hosts or self._allowed_hosts_from_env())
        self.validate_resolution = validate_resolution

    @staticmethod
    def _allowed_hosts_from_env() -> list[str]:
        raw = os.environ.get(ALLOWED_HOSTS_ENV_VAR, "")
        return [host.strip().lower() for host in raw.split(",") if host.strip()]

    def _validate_domain(self, domain: str) -> None:
        """Reject did:web domains that resolve to private/link-local/metadata IPs.

        Prevents SSRF against cloud metadata endpoints such as 169.254.169.254.
        Opt out ONLY via the explicit allowed_hosts constructor param or the
        QTRUST_DID_ALLOWED_HOSTS environment variable (comma-separated hosts).
        """
        if not self.validate_resolution:
            return
        if domain.lower() in self.allowed_hosts:
            return

        try:
            addr_infos = socket.getaddrinfo(domain, None)
        except socket.gaierror as e:
            raise ValueError(f"DID web domain could not be resolved: {domain}") from e

        for info in addr_infos:
            ip = ipaddress.ip_address(info[4][0])
            forbidden = (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
                or ip.is_unspecified
                or str(ip) == "169.254.169.254"
            )
            if forbidden:
                raise ValueError("DID web domain resolves to forbidden address")

    def _did_to_url(self, did: str) -> str:
        """Convert a did:web to an HTTPS URL for the DID document."""
        if not did.startswith("did:web:"):
            raise ValueError(f"Only did:web is supported, got: {did}")

        # did:web:example.com -> https://example.com/.well-known/did.json
        # did:web:example.com:custom-path -> https://example.com/custom-path/did.json
        authority = did[len("did:web:"):]
        parts = authority.split(":")

        domain = parts[0]
        if len(parts) > 1:
            path = "/".join(parts[1:])
            return f"https://{domain}/{path}/did.json"
        else:
            return f"https://{domain}/.well-known/did.json"

    def _parse_did(self, did: str) -> tuple[str, str, str | None]:
        """Parse a DID into (method, identifier, fragment)."""
        if not did.startswith("did:"):
            raise ValueError(f"Invalid DID: {did}")

        without_prefix = did[4:]  # remove "did:"
        method, rest = without_prefix.split(":", 1)

        fragment = None
        if "#" in rest:
            rest, fragment = rest.split("#", 1)

        return method, rest, fragment

    @staticmethod
    def _did_to_domain(identifier: str) -> str:
        """Extract the bare domain (first path segment) from a did:web identifier."""
        return identifier.split(":")[0]

    async def resolve(self, did: str) -> DIDDocument:
        """Resolve a did:web DID asynchronously."""
        method, identifier, _ = self._parse_did(did)

        if method != "web":
            raise ValueError(f"Only did:web is supported, got did:{method}")

        # SSRF guard: reject domains resolving to private/metadata addresses
        self._validate_domain(self._did_to_domain(identifier))

        # Check cache
        cached = self._cache.get(did)
        if cached and (time.time() - cached[1]) < self._cache_ttl:
            return cached[0]

        url = self._did_to_url(did)

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(url)
            resp.raise_for_status()
            data = resp.json()

        doc = DIDDocument(**data)
        self._cache[did] = (doc, time.time())
        return doc

    def resolve_sync(self, did: str) -> DIDDocument:
        """Resolve a did:web DID synchronously."""
        import httpx as httpx_sync

        method, identifier, _ = self._parse_did(did)
        if method != "web":
            raise ValueError(f"Only did:web is supported, got did:{method}")

        # SSRF guard: reject domains resolving to private/metadata addresses
        self._validate_domain(self._did_to_domain(identifier))

        cached = self._cache.get(did)
        if cached and (time.time() - cached[1]) < self._cache_ttl:
            return cached[0]

        url = self._did_to_url(did)

        with httpx_sync.Client(timeout=self.timeout) as client:
            resp = client.get(url)
            resp.raise_for_status()
            data = resp.json()

        doc = DIDDocument(**data)
        self._cache[did] = (doc, time.time())
        return doc

    def get_verification_key(self, doc: DIDDocument, key_id: str | None = None) -> dict[str, Any]:
        """Extract a verification method (public key) from a DID document."""
        methods = doc.verificationMethod
        if not methods:
            raise ValueError("DID document has no verification methods")

        if key_id:
            for method in methods:
                if method.get("id") == key_id:
                    return method
            raise ValueError(f"Verification method {key_id} not found")

        # Return the first one
        return methods[0]

    def get_authentication_key(self, doc: DIDDocument) -> dict[str, Any]:
        """Get the authentication key from a DID document."""
        if not doc.authentication:
            raise ValueError("DID document has no authentication methods")

        auth_ref = doc.authentication[0]
        if isinstance(auth_ref, str):
            # It's a reference — find the matching verification method
            key_id = auth_ref
            if "#" in key_id:
                key_id = key_id.split("#")[-1]
            for method in doc.verificationMethod:
                if method.get("id") == key_id or method["id"] == auth_ref:
                    return method
            raise ValueError(f"Authentication key {auth_ref} not found in verification methods")

        return auth_ref
