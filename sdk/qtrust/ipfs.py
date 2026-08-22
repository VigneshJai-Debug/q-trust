# sdk/qtrust/ipfs.py
"""Pinata IPFS pinning client."""
from __future__ import annotations

import json
import time

import requests


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
