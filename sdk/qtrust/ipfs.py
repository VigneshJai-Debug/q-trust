# sdk/qtrust/ipfs.py
"""Pinata IPFS pinning client."""
from __future__ import annotations

import json

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
        response = requests.post(url, json=payload, headers=self.headers, timeout=30)
        response.raise_for_status()
        return response.json()["IpfsHash"]

    def pin_file(self, file_path: str, name: str | None = None) -> str:
        """Pins a binary file to IPFS. Returns the CID."""
        url = f"{self.BASE_URL}/pinning/pinFileToIPFS"
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

    def unpin(self, cid: str) -> bool:
        """Unpins a file from IPFS."""
        url = f"{self.BASE_URL}/pinning/unpin/{cid}"
        response = requests.delete(url, headers=self.headers, timeout=30)
        return response.status_code == 200
