from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field


class EvidenceEntry(BaseModel):
    index: int = 0
    cbom_hash: str = ""
    prev_hash: str = ""
    entry_hash: str = ""
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    batch_id: str = "default"
    metadata: dict[str, Any] = Field(default_factory=dict)


class EvidenceLedger:
    def __init__(self, batch_id: str | None = None) -> None:
        self.batch_id = batch_id or "default-batch"
        self._entries: list[EvidenceEntry] = []

    @property
    def entries(self) -> list[EvidenceEntry]:
        return self._entries

    @staticmethod
    def _hash_cbom(cbom: dict[str, Any]) -> str:
        canonical = json.dumps(cbom, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode()).hexdigest()

    def _compute_entry_hash(self, entry: EvidenceEntry) -> str:
        data = f"{entry.index}:{entry.cbom_hash}:{entry.prev_hash}:{entry.timestamp}:{entry.batch_id}"
        return hashlib.sha256(data.encode()).hexdigest()

    def append(self, cbom: dict[str, Any]) -> EvidenceEntry:
        prev_hash = self._entries[-1].entry_hash if self._entries else "0" * 64
        cbom_hash = self._hash_cbom(cbom)
        entry = EvidenceEntry(
            index=len(self._entries),
            cbom_hash=cbom_hash,
            prev_hash=prev_hash,
            batch_id=self.batch_id,
        )
        entry.entry_hash = self._compute_entry_hash(entry)
        self._entries.append(entry)
        return entry

    def verify_chain(self) -> bool:
        if not self._entries:
            return True
        for i, entry in enumerate(self._entries):
            expected = self._compute_entry_hash(entry)
            if entry.entry_hash != expected:
                return False
            if i > 0 and entry.prev_hash != self._entries[i - 1].entry_hash:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "batch_id": self.batch_id,
            "entries": [e.model_dump() for e in self._entries],
            "entry_count": len(self._entries),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> EvidenceLedger:
        entries_data = data.get("entries", [])
        if not entries_data:
            raise ValueError("No entries in ledger data")
        ledger = cls(batch_id=data.get("batch_id", "default"))
        for entry_data in entries_data:
            ledger._entries.append(EvidenceEntry(**entry_data))
        return ledger

    def save(self, path: str) -> str:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2)
        return path

    @classmethod
    def load(cls, path: str) -> EvidenceLedger:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return cls.from_dict(data)


class CBOMDiff(BaseModel):
    """Result of comparing two CBOMs."""
    added: list[dict[str, Any]] = Field(default_factory=list)
    removed: list[dict[str, Any]] = Field(default_factory=list)
    modified: list[dict[str, Any]] = Field(default_factory=list)
    summary: dict[str, int] = Field(default_factory=dict)


def compute_cbom_diff(cbom_a: dict[str, Any], cbom_b: dict[str, Any]) -> CBOMDiff:
    def _asset_key(a: dict[str, Any]) -> str:
        parts = [
            str(a.get("host", "")),
            str(a.get("algorithm", "")),
            str(a.get("id", "")),
            str(a.get("name", "")),
        ]
        return ":".join(parts)

    assets_a = {_asset_key(a): a for a in cbom_a.get("assets", [])}
    assets_b = {_asset_key(a): a for a in cbom_b.get("assets", [])}
    added = [assets_b[k] for k in assets_b if k not in assets_a]
    removed = [assets_a[k] for k in assets_a if k not in assets_b]
    modified = []
    for k in assets_a:
        if k in assets_b:
            a, b = assets_a[k], assets_b[k]
            changes = {}
            for field in ("algorithm", "key_size", "criticality", "expired"):
                if a.get(field) != b.get(field):
                    changes[field] = {"from": a.get(field), "to": b.get(field)}
            if changes:
                modified.append({"key": k, "changes": changes, "before": a, "after": b})
    return CBOMDiff(
        added=added,
        removed=removed,
        modified=modified,
        summary={
            "added_count": len(added),
            "removed_count": len(removed),
            "modified_count": len(modified),
            "unchanged_count": len(assets_a) - len(modified),
        },
    )
