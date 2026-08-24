# sdk/qtrust/ipfs.py
"""IPFS pinning clients.

Supports multiple pinning providers selected via ``QTRUST_IPFS_PROVIDERS``
(comma-separated; default ``pinata``). The first listed provider is the
primary — its CID is returned by :meth:`MultiProviderClient.pin_json` /
:meth:`MultiProviderClient.pin_file`. Remaining providers pin best-effort
concurrently; CID mismatches are logged as warnings.
"""
from __future__ import annotations

import json
import logging
import os
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from typing import Any

import requests

logger = logging.getLogger(__name__)

PROVIDERS_ENV_VAR = "QTRUST_IPFS_PROVIDERS"
PINATA_KEY_ENV_VAR = "QTRUST_PINATA_API_KEY"
PINATA_SECRET_ENV_VAR = "QTRUST_PINATA_API_SECRET"
KUBO_API_ENV_VAR = "QTRUST_IPFS_KUBO_API"
KUBO_USER_ENV_VAR = "QTRUST_IPFS_KUBO_USER"
KUBO_PASS_ENV_VAR = "QTRUST_IPFS_KUBO_PASS"
WEB3_STORAGE_TOKEN_ENV_VAR = "QTRUST_WEB3_STORAGE_TOKEN"

DEFAULT_KUBO_API = "http://127.0.0.1:5001"


class PinataClient:
    """Pins files and JSON to IPFS via the Pinata API."""

    BASE_URL = "https://api.pinata.cloud"

    def __init__(self, api_key: str, api_secret: str):
        self.api_key = api_key
        self.api_secret = api_secret
        self.headers = {
            "pinata_api_key": api_key,
            "pinata_secret_api_key": api_secret,
        }

    def pin_json(self, json_str: str, name: str | None = None) -> str:
        """Pins a JSON string to IPFS. Returns the CID."""
        url = f"{self.BASE_URL}/pinning/pinJSONToIPFS"
        payload = {"pinataContent": json.loads(json_str)}
        if name:
            payload["pinataMetadata"] = {"name": name}
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                response = requests.post(url, json=payload, headers=self.headers, timeout=30)
                response.raise_for_status()
                return response.json()["IpfsHash"]
            except (requests.RequestException, KeyError) as exc:
                last_exc = exc
                if attempt < 2:
                    time.sleep(2 ** attempt)
        raise last_exc  # type: ignore[misc]

    def pin_file(self, file_path: str, name: str | None = None) -> str:
        """Pins a binary file to IPFS. Returns the CID."""
        url = f"{self.BASE_URL}/pinning/pinFileToIPFS"
        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                with open(file_path, "rb") as f:
                    files = {"file": (name or file_path.split("/")[-1], f)}
                    metadata = {"name": name or file_path.split("/")[-1]}
                    response = requests.post(
                        url,
                        files=files,
                        data={"pinataMetadata": json.dumps(metadata)},
                        headers=self.headers,
                        timeout=300,
                    )
                response.raise_for_status()
                return response.json()["IpfsHash"]
            except (requests.RequestException, KeyError) as exc:
                last_exc = exc
                if attempt < 2:
                    time.sleep(2 ** attempt)
        raise last_exc  # type: ignore[misc]

    def unpin(self, cid: str) -> bool:
        """Unpins a file from IPFS."""
        url = f"{self.BASE_URL}/pinning/unpin/{cid}"
        response = requests.delete(url, headers=self.headers, timeout=30)
        return response.status_code == 200


class MultiPinataClient:
    """Pins files and JSON to IPFS via multiple Pinata API key/secret pairs.

    Tries each client in order as a fallback chain. Raises on failure only if
    all clients fail.
    """

    def __init__(self, credentials: list[tuple[str, str]]):
        """Initialize with a list of (api_key, api_secret) pairs."""
        if not credentials:
            raise ValueError("At least one set of credentials is required")
        self.clients = [PinataClient(key, secret) for key, secret in credentials]

    def pin_json(self, json_str: str, name: str | None = None) -> str:
        """Pins a JSON string to IPFS using fallback clients. Returns the CID."""
        last_exc: Exception | None = None
        for client in self.clients:
            try:
                return client.pin_json(json_str, name)
            except Exception as exc:
                last_exc = exc
        raise last_exc  # type: ignore[misc]

    def pin_file(self, file_path: str, name: str | None = None) -> str:
        """Pins a binary file to IPFS using fallback clients. Returns the CID."""
        last_exc: Exception | None = None
        for client in self.clients:
            try:
                return client.pin_file(file_path, name)
            except Exception as exc:
                last_exc = exc
        raise last_exc  # type: ignore[misc]

    def unpin(self, cid: str) -> bool:
        """Unpins a file from IPFS using the first available client."""
        for client in self.clients:
            try:
                return client.unpin(cid)
            except Exception:
                continue
        return False


class KuboProvider:
    """Pins content to a Kubo (go-ipfs) node via its HTTP API."""

    def __init__(
        self,
        api_url: str | None = None,
        user: str | None = None,
        password: str | None = None,
    ):
        self.api_url = (
            api_url or os.environ.get(KUBO_API_ENV_VAR) or DEFAULT_KUBO_API
        ).rstrip("/")
        user = user if user is not None else os.environ.get(KUBO_USER_ENV_VAR)
        password = password if password is not None else os.environ.get(KUBO_PASS_ENV_VAR)
        self.auth = (user, password) if user is not None and password is not None else None

    def pin_json(self, json_str: str, name: str | None = None) -> str:
        """Pins a JSON string via ``POST /api/v0/add?pin=true``. Returns the CID."""
        url = f"{self.api_url}/api/v0/add?pin=true"
        files = {"file": (name or "payload.json", json_str)}
        response = requests.post(url, files=files, auth=self.auth, timeout=30)
        response.raise_for_status()
        return response.json()["Hash"]

    def pin_file(self, file_path: str, name: str | None = None) -> str:
        """Pins a binary file via ``POST /api/v0/add?pin=true``. Returns the CID."""
        url = f"{self.api_url}/api/v0/add?pin=true"
        filename = name or file_path.split("/")[-1]
        with open(file_path, "rb") as f:
            response = requests.post(
                url, files={"file": (filename, f)}, auth=self.auth, timeout=300
            )
        response.raise_for_status()
        return response.json()["Hash"]


class Web3StorageProvider:
    """Pins content via the web3.storage upload API (Bearer token auth)."""

    BASE_URL = "https://api.web3.storage"

    def __init__(self, token: str):
        self.token = token
        self.headers = {"Authorization": f"Bearer {token}"}

    @staticmethod
    def _extract_cid(response: requests.Response) -> str:
        cid = response.headers.get("X-Digest")
        if not cid:
            body = response.json()
            if isinstance(body, dict):
                cid = body.get("cid")
        if not cid:
            raise KeyError("no CID in web3.storage response")
        return cid

    def pin_json(self, json_str: str, name: str | None = None) -> str:
        """Uploads a JSON string to web3.storage. Returns the CID."""
        files = {"file": (name or "payload.json", json_str)}
        response = requests.post(
            f"{self.BASE_URL}/upload", files=files, headers=self.headers, timeout=30
        )
        response.raise_for_status()
        return self._extract_cid(response)

    def pin_file(self, file_path: str, name: str | None = None) -> str:
        """Uploads a binary file to web3.storage. Returns the CID."""
        filename = name or file_path.split("/")[-1]
        with open(file_path, "rb") as f:
            response = requests.post(
                f"{self.BASE_URL}/upload",
                files={"file": (filename, f)},
                headers=self.headers,
                timeout=300,
            )
        response.raise_for_status()
        return self._extract_cid(response)


class MultiProviderClient:
    """Pins via a primary provider, replicating to the rest best-effort.

    Success means the primary provider pinned successfully; its CID is
    returned. If the primary fails, the other providers race concurrently and
    the first (in configuration order) successful CID is returned with a
    warning. Raises only if every configured provider fails.
    """

    def __init__(self, providers: list[tuple[str, Any]]):
        if not providers:
            raise ValueError("At least one IPFS provider is required")
        self.providers = providers

    @classmethod
    def from_env(cls, env: dict[str, str] | None = None) -> MultiProviderClient:
        """Build a client from environment configuration.

        ``QTRUST_IPFS_PROVIDERS`` (default ``pinata``) selects and orders the
        providers. Providers whose credentials are absent from the environment
        are skipped with a warning.
        """
        env = env if env is not None else dict(os.environ)
        raw = env.get(PROVIDERS_ENV_VAR, "pinata")
        names = [name.strip().lower() for name in raw.split(",") if name.strip()]
        if not names:
            names = ["pinata"]

        providers: list[tuple[str, Any]] = []
        for name in names:
            provider = create_provider(name, env)
            if provider is None:
                logger.warning("IPFS provider '%s' skipped: credentials not configured", name)
                continue
            providers.append((name, provider))

        if not providers:
            raise ValueError(
                f"No usable IPFS providers configured ({PROVIDERS_ENV_VAR}={raw!r})"
            )
        return cls(providers)

    def pin_json(self, json_str: str, name: str | None = None) -> str:
        """Pins a JSON string across providers. Returns the primary CID."""
        return self._pin_all("pin_json", (json_str, name))

    def pin_file(self, file_path: str, name: str | None = None) -> str:
        """Pins a binary file across providers. Returns the primary CID."""
        return self._pin_all("pin_file", (file_path, name))

    def _invoke(self, provider: Any, method: str, args: tuple) -> str:
        fn: Callable[..., str] = getattr(provider, method)
        return fn(*args)

    def _pin_all(self, method: str, args: tuple) -> str:
        primary_name, primary = self.providers[0]
        rest = self.providers[1:]

        try:
            primary_cid = self._invoke(primary, method, args)
        except Exception as primary_exc:
            if not rest:
                raise primary_exc
            logger.warning(
                "Primary IPFS provider '%s' failed (%s); trying %d fallback(s)",
                primary_name, primary_exc, len(rest),
            )
            return self._race_fallback(rest, method, args, primary_name, primary_exc)

        if rest:
            self._replicate(rest, method, args, primary_name, primary_cid)
        return primary_cid

    def _run_concurrently(
        self, providers: list[tuple[str, Any]], method: str, args: tuple
    ) -> list[tuple[str, str | None, Exception | None]]:
        results: list[tuple[str, str | None, Exception | None]] = []

        with ThreadPoolExecutor(max_workers=max(1, len(providers))) as pool:
            futures = [
                (pname, pool.submit(self._invoke, provider, method, args))
                for pname, provider in providers
            ]
            for pname, future in futures:
                try:
                    results.append((pname, future.result(), None))
                except Exception as exc:
                    results.append((pname, None, exc))
        return results

    def _replicate(
        self,
        providers: list[tuple[str, Any]],
        method: str,
        args: tuple,
        primary_name: str,
        primary_cid: str,
    ) -> None:
        for pname, cid, exc in self._run_concurrently(providers, method, args):
            if exc is not None:
                logger.warning(
                    "Best-effort pin on '%s' failed: %s (primary '%s' succeeded)",
                    pname, exc, primary_name,
                )
            elif cid != primary_cid:
                logger.warning(
                    "CID mismatch on '%s': got %s, primary '%s' returned %s",
                    pname, cid, primary_name, primary_cid,
                )

    def _race_fallback(
        self,
        providers: list[tuple[str, Any]],
        method: str,
        args: tuple,
        primary_name: str,
        primary_exc: Exception,
    ) -> str:
        last_exc: Exception | None = primary_exc
        for pname, cid, exc in self._run_concurrently(providers, method, args):
            if cid is not None:
                logger.warning(
                    "Primary IPFS provider '%s' failed (%s); using CID %s from '%s'",
                    primary_name, primary_exc, cid, pname,
                )
                return cid
            last_exc = exc
        raise last_exc  # type: ignore[misc]

    def unpin(self, cid: str) -> bool:
        """Unpins from every provider; True if any provider unpinned."""
        for _, provider in self.providers:
            try:
                if provider.unpin(cid):
                    return True
            except Exception:
                continue
        return False


def create_provider(name: str, env: dict[str, str] | None = None) -> Any | None:
    """Instantiate a named provider from environment config.

    Returns None when the provider's credentials are not configured. Raises
    ValueError for unknown provider names.
    """
    env = env if env is not None else dict(os.environ)
    if name == "pinata":
        key = env.get(PINATA_KEY_ENV_VAR)
        secret = env.get(PINATA_SECRET_ENV_VAR)
        if not (key and secret):
            return None
        return PinataClient(api_key=key, api_secret=secret)
    if name == "kubo":
        return KuboProvider(
            api_url=env.get(KUBO_API_ENV_VAR),
            user=env.get(KUBO_USER_ENV_VAR),
            password=env.get(KUBO_PASS_ENV_VAR),
        )
    if name in ("web3", "web3storage"):
        token = env.get(WEB3_STORAGE_TOKEN_ENV_VAR)
        if not token:
            return None
        return Web3StorageProvider(token=token)
    raise ValueError(
        f"Unknown IPFS provider '{name}' (expected pinata, kubo, or web3)"
    )


def create_ipfs_client(env: dict[str, str] | None = None) -> MultiProviderClient:
    """Create an env-configured multi-provider IPFS client."""
    return MultiProviderClient.from_env(env)
