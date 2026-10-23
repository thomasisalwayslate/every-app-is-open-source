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

    def save(self, operation: str, classification: str, data, limitations=None, provenance=None):
        if classification not in {"fact", "computed", "guess"}:
            raise ValueError("Unknown evidence classification")
        payload = {"target_sha256": self.target_sha256,
                  "operation": operation, "classification": classification,
                  "limitations": limitations or [], "data": data}
        if provenance is not None:
            payload['analysis'] = provenance
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
        identifier = hashlib.sha256(canonical).hexdigest()[:32]
        path = self.directory / f"{identifier}.json"
        record = {"id": identifier, **payload}
        raw = json.dumps(record, ensure_ascii=False, indent=2, sort_keys=True).encode()
        if path.exists() and path.read_bytes() != raw:
            raise ValueError('Evidence identity collision or existing record changed')
        if not path.exists():
            with path.open('xb') as output:
                output.write(raw)
        digest = hashlib.sha256(raw).hexdigest()
        checksum = self.directory / f"{identifier}.sha256"
        if checksum.exists():
            if checksum.read_text() != digest+'\n':
                raise ValueError('Evidence checksum changed')
        else:
            with checksum.open('x') as output:
                output.write(digest+'\n')
        return {"id": identifier, "path": str(path), "uri": path.as_uri(),
                "sha256": digest, "target_sha256": self.target_sha256}

    def artifact(self, text, suffix='.c'):
        """Content-address raw output too: later analysis cannot overwrite it."""
        raw = text.encode('utf-8')
        digest = hashlib.sha256(raw).hexdigest()
        path = self.directory / ('artifact-'+digest+suffix)
        if path.exists():
            if path.read_bytes() != raw:
                raise ValueError('Raw evidence artifact hash mismatch')
        else:
            with path.open('xb') as output:
                output.write(raw)
        return {'uri': path.as_uri(), 'sha256': digest, 'bytes': len(raw)}

    def read(self, identifier: str, offset: int = 0, limit: int = 12000):
        if not re.fullmatch(r"[0-9a-f]{32}", identifier):
            raise ValueError("Use an evidence id returned by this program's tools")
        if offset < 0 or not 1 <= limit <= 40000:
            raise ValueError("offset must be nonnegative; limit must be 1..40000")
        path = self.directory / f"{identifier}.json"
        raw = path.read_bytes()
        if hashlib.sha256(raw).hexdigest() != (path.with_suffix('.sha256')).read_text().strip():
            raise ValueError("Evidence hash mismatch")
        try:
            record = json.loads(raw)
            if not isinstance(record, dict) or record.get('target_sha256') != self.target_sha256:
                raise ValueError('Evidence belongs to another target')
            payload = {key:value for key,value in record.items() if key != 'id'}
            canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()
            if record.get('id') != identifier or hashlib.sha256(canonical).hexdigest()[:32] != identifier:
                raise ValueError('Evidence content identity mismatch')
        except (UnicodeError, json.JSONDecodeError) as error:
            raise ValueError('Evidence record is corrupt') from error
        text = raw.decode()
        return {"classification": "fact", "id": identifier, "uri": path.as_uri(),
                "offset": offset, "text": text[offset:offset+limit],
                "next_offset": offset + limit if offset + limit < len(text) else None}
