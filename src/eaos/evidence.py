"""Durable, content-checked evidence stored alongside the input program."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path


class Evidence:
    def __init__(self, directory: Path, target_sha256: str):
        self.directory = directory
        directory.mkdir(parents=True, exist_ok=True)
        self.target_sha256 = target_sha256

    def save(self, operation: str, classification: str, data, limitations=None):
        if classification not in {"fact", "computed", "guess"}:
            raise ValueError("Unknown evidence classification")
        payload = {"target_sha256": self.target_sha256,
                  "operation": operation, "classification": classification,
                  "limitations": limitations or [], "data": data}
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        identifier = hashlib.sha256(canonical).hexdigest()[:32]
        path = self.directory / f"{identifier}.json"
        record = {"id": identifier, **payload}
        raw = json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True).encode()
        if path.exists() and path.read_bytes() != raw:
            raise ValueError('Evidence identity collision or existing record changed')
        path.write_bytes(raw)
        digest = hashlib.sha256(raw).hexdigest()
        (self.directory / f"{identifier}.sha256").write_text(digest + "\n")
        return {"id": identifier, "path": str(path), "uri": path.as_uri(),
                "sha256": digest, "target_sha256": self.target_sha256}

    def read(self, identifier: str, offset: int = 0, limit: int = 12000):
        if not re.fullmatch(r"[0-9a-f]{32}", identifier):
            raise ValueError("Use an evidence id returned by this program's tools")
        if offset < 0 or not 1 <= limit <= 40000:
            raise ValueError("offset must be nonnegative; limit must be 1..40000")
        path = self.directory / f"{identifier}.json"
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != (path.with_suffix('.sha256')).read_text().strip():
            raise ValueError("Evidence hash mismatch")
        text = raw.decode()
        return {"classification": "fact", "id": identifier, "uri": path.as_uri(),
                "offset": offset, "text": text[offset:offset+limit],
                "next_offset": offset + limit if offset + limit < len(text) else None}
