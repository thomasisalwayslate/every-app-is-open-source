"""Bounded selected-root inventory and immutable component capture.

Original bundles are read only. Symlinks are recorded, never followed. All
capture/cache files live in an explicitly selected workspace outside the root.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import posixpath
import re
import stat
import struct
import tempfile
import time

from . import identity
from .js_index import SyntaxOwner, inspect_index, digest as syntax_digest
from .js_syntax import SOURCE_LIMIT, parser_identity

SCHEMA = 1
DEFAULT_LIMITS = {'files': 10000, 'depth': 16, 'file_bytes': 128 * 1024 * 1024,
                  'total_bytes': 512 * 1024 * 1024, 'seconds': 15.0,
                  'asar_header_bytes': 8 * 1024 * 1024, 'asar_entries': 10000,
                  'javascript_bytes': SOURCE_LIMIT}


def _digest(data):
    return hashlib.sha256(data).hexdigest()


def _key(value):
    return _digest(_encoded(value))


def _encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def _unique(pairs):
    out = {}
    for name, value in pairs:
        if name in out:
            raise ValueError('Duplicate JSON key')
        out[name] = value
    return out


# Declared SHA-256 admission and subtraction-based member range checks adapted
# from REA src/artifacts/AsarArtifactReader.ts, commit
# 96ea32b7e4e28d3c9cd79a1de4b8e1ba3b4244e9, Copyright (c) 2026 morluto,
# MIT License. Exact upstream permission notice is retained in NOTICE.
# EAOS additionally fails unsupported declarations rather than treating them as
# absent, and compares the captured member's complete SHA-256 before use.
def _declared_integrity(value, member_size):
    result = {'trust': 'untrusted_archive_metadata', 'status': 'unsupported',
              'verification_scope': 'whole_member_sha256_only',
              'block_hashes_checked': False}
    if not isinstance(value, dict):
        return dict(result, reason='integrity declaration must be an object')
    algorithm, digest = value.get('algorithm'), value.get('hash')
    result['algorithm'] = algorithm if isinstance(algorithm, str) and len(algorithm) <= 64 else None
    result['hash'] = digest if isinstance(digest, str) and len(digest) <= 128 else None
    if algorithm != 'SHA256':
        return dict(result, reason='unsupported declared integrity algorithm; expected SHA256')
    if not isinstance(digest, str) or re.fullmatch('[a-f0-9]{64}', digest) is None:
        return dict(result, reason='declared SHA256 must be 64 lowercase hexadecimal characters')
    if set(value) - {'algorithm', 'hash', 'blockSize', 'blocks'}:
        return dict(result, reason='unsupported declared integrity fields')
    if ('blocks' in value) != ('blockSize' in value):
        return dict(result, reason='unsupported partial block-integrity layout')
    if 'blocks' in value:
        size, blocks = value['blockSize'], value['blocks']
        if isinstance(size, bool) or not isinstance(size, int) or size <= 0 or not isinstance(blocks, list):
            return dict(result, reason='unsupported block-integrity layout')
        if len(blocks) != (member_size + size - 1) // size or any(not isinstance(block, str) or re.fullmatch('[a-f0-9]{64}', block) is None for block in blocks):
            return dict(result, reason='unsupported block hash count or encoding')
        result['declared_block_count'] = len(blocks)
    return dict(result, status='supported_sha256_unverified')


def asar_entries(data, total_size, *, max_header=8 * 1024 * 1024, max_entries=10000, cancelled=None):
    """Read bounded Chromium pickle/ASAR metadata, without extracting anything."""
    if len(data) < 16:
        raise ValueError('Truncated ASAR header')
    size_payload, header_size, payload_size, string_size = struct.unpack_from('<IIII', data)
    if size_payload != 4 or header_size < 8 or header_size > max_header or header_size % 4:
        raise ValueError('Unsupported ASAR header pickle')
    if 8 + header_size > len(data) or payload_size + 4 != header_size or string_size > payload_size - 4:
        raise ValueError('Truncated or inconsistent ASAR header')
    if 8 + header_size > total_size:
        raise ValueError('ASAR data starts outside archive')
    try:
        header = json.loads(data[16:16 + string_size].decode('utf-8'), object_pairs_hook=_unique)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError('Invalid ASAR JSON header') from exc
    if not isinstance(header, dict) or not isinstance(header.get('files'), dict):
        raise ValueError('Unsupported ASAR root layout')
    entries, gaps, ranges = [], [], []
    def visit(files, prefix='', depth=0):
        if depth > 64:
            raise ValueError('ASAR directory nesting exceeds budget')
        for name in sorted(files):
            if cancelled and cancelled():
                raise InterruptedError('ASAR inventory cancelled')
            if len(entries) >= max_entries:
                gaps.append({'path': prefix, 'reason': 'asar_entry_budget'})
                return
            node = files[name]
            if not isinstance(name, str) or not name or name in ('.', '..') or '/' in name or '\\' in name or '\0' in name:
                raise ValueError('Unsafe ASAR entry name')
            if not isinstance(node, dict):
                raise ValueError('Invalid ASAR entry')
            path = prefix + name
            if 'link' in node:
                entries.append({'path': path, 'kind': 'asar_link', 'capturable': False})
                continue
            if 'files' in node:
                if not isinstance(node['files'], dict):
                    raise ValueError('Invalid ASAR directory')
                entries.append({'path': path, 'kind': 'asar_directory', 'capturable': False})
                visit(node['files'], path + '/', depth + 1)
                continue
            size = node.get('size')
            if isinstance(size, bool) or not isinstance(size, int) or size < 0:
                raise ValueError('Invalid ASAR entry size')
            if 'unpacked' in node and not isinstance(node['unpacked'], bool):
                raise ValueError('Invalid ASAR unpacked marker')
            integrity = _declared_integrity(node['integrity'], size) if 'integrity' in node else None
            if node.get('unpacked') is True:
                entry = {'path': path, 'kind': 'asar_unpacked', 'size': size, 'capturable': False,
                         'reason': 'unpacked companion capture is unsupported'}
                if integrity is not None:
                    entry['declared_integrity'] = integrity
                entries.append(entry)
                gaps.append({'path': path, 'reason': 'asar_unpacked_bytes_not_captured'})
                continue
            offset = node.get('offset')
            if not isinstance(offset, str) or not offset.isascii() or not offset.isdecimal() or len(offset) > 20:
                raise ValueError('Invalid ASAR entry offset')
            offset = int(offset) + 8 + header_size
            if offset > total_size or size > total_size - offset:
                raise ValueError('ASAR entry escapes archive')
            if size:
                ranges.append((offset, offset + size))
            entry = {'path': path, 'kind': 'asar_file', 'offset': offset,
                     'size': size, 'capturable': True}
            if integrity is not None:
                entry['declared_integrity'] = integrity
            entries.append(entry)
    visit(header['files'])
    ranges.sort()
    if any(a[1] > b[0] for a, b in zip(ranges, ranges[1:])):
        raise ValueError('Overlapping ASAR entries')
    return {'entries': entries, 'gaps': gaps, 'complete': not gaps,
            'data_offset': 8 + header_size}


class Application:
    def __init__(self, root, workspace, *, limits=None, cancelled=None):
        root = Path(root).expanduser()
        if root.is_symlink() or not root.is_dir():
            raise ValueError('Selected application root must be a real directory')
        self.root = root.resolve()
        self.workspace = Path(workspace).expanduser().resolve()
        bundle_suffixes = {'.app', '.appex', '.framework', '.bundle', '.xpc', '.plugin', '.kext'}
        if any(part.suffix.lower() in bundle_suffixes for part in (self.workspace, *self.workspace.parents)):
            raise ValueError('Application workspace must be outside all signed bundles')
        if self.workspace == self.root or self.workspace.is_relative_to(self.root):
            raise ValueError('Application workspace must be outside selected root')
        self.limits = dict(DEFAULT_LIMITS)
        if limits:
            if set(limits) - set(self.limits):
                raise ValueError('Unknown application inventory limit')
            self.limits.update(limits)
        for key, value in self.limits.items():
            if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
                raise ValueError('Inventory limits must be positive finite numbers')
            if value != value or value == float('inf'):
                raise ValueError('Inventory limits must be finite')
            if key != 'seconds' and not isinstance(value, int):
                raise ValueError('Inventory count/byte limits must be integers')
        self.cancelled = cancelled
        self._manifest = None
        self._deadline = 0
        self.syntax_owner = SyntaxOwner()

    def close(self):
        self.syntax_owner.close()

    def _check(self):
        if self.cancelled and self.cancelled():
            raise InterruptedError('Application operation cancelled')
        if self._deadline and time.monotonic() >= self._deadline:
            raise TimeoutError('Application operation time budget')

    def _open(self, relative):
        parts = PurePosixPath(relative).parts
        if not parts or any(x in ('', '.', '..') for x in parts) or PurePosixPath(relative).is_absolute():
            raise ValueError('Invalid captured component path')
        rootfd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        fd = rootfd
        try:
            for part in parts[:-1]:
                nextfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                if fd != rootfd:
                    os.close(fd)
                fd = nextfd
            final = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
            if not stat.S_ISREG(os.fstat(final).st_mode):
                os.close(final)
                raise ValueError('Component is not a regular file')
            return os.fdopen(final, 'rb')
        finally:
            if fd != rootfd:
                os.close(fd)
            os.close(rootfd)

    def _bytes(self, relative, max_bytes):
        self._check()
        with self._open(relative) as source:
            before = os.fstat(source.fileno())
            if before.st_size > max_bytes:
                raise ValueError('Component exceeds byte budget')
            chunks = []
            remaining = max_bytes + 1
            while remaining:
                self._check()
                data = source.read(min(1024 * 1024, remaining))
                if not data:
                    break
                chunks.append(data)
                remaining -= len(data)
            after = os.fstat(source.fileno())
            if (before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise ValueError('Component changed while reading; inventory again')
            data = b''.join(chunks)
            if len(data) > max_bytes:
                raise ValueError('Component exceeds byte budget')
            return data

    def _folder(self, *parts):
        folder = self.workspace
        folder.mkdir(parents=True, exist_ok=True)
        for part in parts:
            folder = folder / part
            if folder.is_symlink():
                raise ValueError('Workspace cache contains a symlink')
            folder.mkdir(exist_ok=True)
        if not folder.resolve().is_relative_to(self.workspace):
            raise ValueError('Workspace cache escapes selected workspace')
        return folder

    def _save(self, manifest):
        folder = self._folder('inventories')
        path = folder / (manifest['snapshot'] + '.json')
        payload = _encoded(manifest)
        if path.is_symlink():
            raise ValueError('Inventory cache must not be a symlink')
        if path.exists():
            if path.read_bytes() != payload:
                raise ValueError('Inventory snapshot cache conflicts with captured identity')
            return
        fd, temp = tempfile.mkstemp(dir=folder)
        try:
            with os.fdopen(fd, 'wb') as out:
                out.write(payload)
                out.flush()
                os.fsync(out.fileno())
            os.chmod(temp, 0o444)
            os.link(temp, path)
        finally:
            os.unlink(temp)

    def _walk(self, entries, gaps):
        """A bounded fwalk equivalent: never materialize an unbounded directory."""
        stack = [Path('.')]
        while stack:
            self._check()
            relative = stack.pop()
            fd = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                for part in relative.parts:
                    nextfd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                    os.close(fd)
                    fd = nextfd
                names = []
                remaining = self.limits['files'] - len(entries)
                with os.scandir(fd) as scan:
                    for item in scan:
                        self._check()
                        if len(names) >= remaining:
                            gaps.append({'path': relative.as_posix(), 'reason': 'entry_budget'})
                            break
                        names.append((item.name, item.is_dir(follow_symlinks=False)))
                names.sort()
                dirs = [name for name, directory in names if directory]
                files = [name for name, directory in names if not directory]
                yield self.root / relative, dirs, files, fd
                stack.extend(relative / name for name in reversed(dirs))
            except InterruptedError:
                raise
            except OSError as exc:
                gaps.append({'path': relative.as_posix(), 'reason': 'inaccessible_directory: ' + str(exc)})
            finally:
                os.close(fd)

    def _scan(self):
        self._deadline = time.monotonic() + self.limits['seconds']
        entries, gaps, total = [], [], 0
        stopped = False
        try:
            for directory, dirs, files, dirfd in self._walk(entries, gaps):
                self._check()
                rel_dir = Path(directory).relative_to(self.root)
                depth = len(rel_dir.parts)
                dirs.sort()
                files.sort()
                names = [(name, True) for name in dirs] + [(name, False) for name in files]
                for name, isdir in names:
                    self._check()
                    if len(entries) >= self.limits['files']:
                        gaps.append({'path': rel_dir.as_posix(), 'reason': 'entry_budget'})
                        stopped = True
                        break
                    relative = (rel_dir / name).as_posix()
                    try:
                        info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
                        if stat.S_ISLNK(info.st_mode):
                            entries.append({'path': relative, 'kind': 'symlink', 'capturable': False,
                                            'link_target': os.readlink(name, dir_fd=dirfd)})
                            if name in dirs:
                                dirs.remove(name)
                            continue
                        if isdir:
                            directory_row = {'path': relative, 'kind': 'directory', 'capturable': False}
                            if name.endswith(('.framework', '.app', '.xpc', '.appex')):
                                directory_row['layout_role'] = {'value': name.rsplit('.', 1)[1], 'classification': 'guess', 'basis': 'directory suffix only'}
                            entries.append(directory_row)
                            if depth + 1 >= self.limits['depth']:
                                dirs.remove(name)
                                gaps.append({'path': relative, 'reason': 'depth_budget'})
                            continue
                        if not stat.S_ISREG(info.st_mode):
                            entries.append({'path': relative, 'kind': 'unsupported_file', 'capturable': False})
                            continue
                        row = {'path': relative, 'size': info.st_size, 'kind': 'resource', 'capturable': False}
                        if info.st_size > self.limits['file_bytes'] or total + info.st_size > self.limits['total_bytes']:
                            row['reason'] = 'file_byte_budget' if info.st_size > self.limits['file_bytes'] else 'total_byte_budget'
                            # Large executable candidates remain visible even when
                            # hashing/capture is refused by the byte budget.
                            with self._open(relative) as source:
                                header = source.read(8192)
                            if header[:4] in identity.THIN or header[:4] in identity.FAT:
                                row['kind'] = 'native'
                                row['architectures'] = self._architectures(header)
                                row['architecture_validation'] = 'header candidates only; uncaptured byte-budget omission'

                            gaps.append({'path': relative, 'reason': row['reason']})
                            entries.append(row)
                            continue
                        data = self._bytes(relative, self.limits['file_bytes'])
                        total += len(data)
                        row.update(size=len(data), sha256=_digest(data), capturable=True)
                        if data[:4] in identity.THIN or data[:4] in identity.FAT:
                            row['kind'] = 'native'
                            # Architecture parsing reads only the already captured bytes.
                            row['architectures'] = self._architectures(data)
                            row['architecture_validation'] = 'header candidates only; capture validates selected slice'
                        elif relative.endswith(('.js', '.cjs', '.mjs')):
                            row['kind'] = 'javascript'
                        elif name == 'Info.plist':
                            row['kind'] = 'plist'
                            try:
                                if len(data) > self.limits['asar_header_bytes']:
                                    raise ValueError('Plist exceeds metadata byte budget')
                                value = plistlib.loads(data)
                                if isinstance(value, dict):
                                    row['bundle'] = {key: value[key] for key in ('CFBundleIdentifier', 'CFBundleExecutable', 'CFBundlePackageType', 'CFBundleShortVersionString') if isinstance(value.get(key), str)}
                            except Exception as exc:
                                row['parse_error'] = type(exc).__name__
                                gaps.append({'path': relative, 'reason': 'unparsed_plist'})
                        elif name == 'package.json':
                            row['kind'] = 'package_json'
                            try:
                                if len(data) > self.limits['asar_header_bytes']:
                                    raise ValueError('Package exceeds metadata byte budget')
                                package = json.loads(data, object_pairs_hook=_unique)
                                if not isinstance(package, dict):
                                    raise ValueError('Package root must be an object')
                                row['package'] = {key: package[key] for key in ('name', 'version', 'main', 'type') if isinstance(package.get(key), str)}
                            except (ValueError, UnicodeError, RecursionError):
                                row['parse_error'] = 'invalid_package_json'
                                gaps.append({'path': relative, 'reason': 'unparsed_package_json'})
                        elif name.endswith('.asar'):
                            row['kind'] = 'asar'
                            try:
                                if len(entries) + 1 >= self.limits['files']:
                                    row['asar_complete'] = False
                                    gaps.append({'path': relative, 'reason': 'asar_entry_budget'})
                                    entries.append(row)
                                    continue
                                archive = asar_entries(data, len(data), max_header=self.limits['asar_header_bytes'], max_entries=min(self.limits['asar_entries'], max(1, self.limits['files'] - len(entries) - 1)), cancelled=self.cancelled)
                                row['asar_complete'] = archive['complete']
                                entries.append(row)
                                for item in archive['entries']:
                                    embedded = dict(item, path=relative + '!/' + item['path'], archive=relative,
                                                    archive_sha256=row['sha256'], archive_path=item['path'])
                                    if item['kind'] == 'asar_file' and item['path'].endswith(('.js', '.cjs', '.mjs')):
                                        embedded['kind'] = 'javascript'
                                    if item['kind'] == 'asar_file' and PurePosixPath(item['path']).name == 'package.json':
                                        embedded['kind'] = 'package_json'
                                        try:
                                            package = json.loads(data[item['offset']:item['offset']+item['size']], object_pairs_hook=_unique)
                                            if not isinstance(package, dict):
                                                raise ValueError('Package root must be object')
                                            embedded['package'] = {key: package[key] for key in ('name', 'version', 'main', 'type') if isinstance(package.get(key), str)}
                                        except (ValueError, UnicodeError, RecursionError):
                                            embedded['parse_error'] = 'invalid_package_json'
                                            gaps.append({'path': embedded['path'], 'reason': 'unparsed_package_json'})
                                    entries.append(embedded)
                                gaps.extend({'path': relative + '!/' + gap['path'], 'reason': gap['reason']} for gap in archive['gaps'])
                                continue
                            except ValueError as exc:
                                row['parse_error'] = str(exc)
                                gaps.append({'path': relative, 'reason': 'unsupported_asar_metadata'})
                        entries.append(row)
                    except InterruptedError:
                        raise
                    except (OSError, ValueError) as exc:
                        gaps.append({'path': relative, 'reason': type(exc).__name__ + ': ' + str(exc)})
                if stopped:
                    break
        except TimeoutError:
            gaps.append({'path': '.', 'reason': 'time_budget'})
        finally:
            self._deadline = 0
        entries.sort(key=lambda row: row['path'])
        for row in entries:
            row['component_id'] = _key({'schema': SCHEMA, 'root': str(self.root), 'component': row})
        by_path = {row['path']: row for row in entries}
        relationships = []
        for row in entries:
            main = row.get('package', {}).get('main')
            if not main:
                continue
            archive_prefix, separator, internal = row['path'].partition('!/')
            package_path = internal if separator else row['path']
            candidate = posixpath.normpath(posixpath.join(posixpath.dirname(package_path), main))
            safe = not candidate.startswith('../') and candidate != '..' and not candidate.startswith('/') and '\\' not in candidate
            candidate_path = archive_prefix + '!/' + candidate if separator else candidate
            target = by_path.get(candidate_path) if safe else None
            relationships.append({'kind': 'declared_package_entry', 'classification': 'computed',
                                  'source_component_id': row['component_id'], 'literal_main': main,
                                  'target_component_id': target['component_id'] if target else None,
                                  'candidate_path': candidate_path if safe else None,
                                  'status': 'recorded_exact_path' if target else 'unresolved',
                                  'limitation': 'Package declaration and path match only; execution and module resolution are not established.'})
        value = {'schema': SCHEMA, 'root': str(self.root), 'entries': entries, 'relationships': relationships,
                 'coverage': {'complete': not gaps, 'entries': len(entries), 'bytes_hashed': total,
                              'gaps': gaps, 'scope': 'selected-root inventory only; no program analysis'},
                 'limitations': ['Child symlinks are recorded but never followed.',
                                 'Component coverage does not establish whole-application behavior.',
                                 'Paths and literal metadata are observations; framework/helper roles are inferred from layout.']}
        value['snapshot'] = _key(value)
        self._save(value)
        self._manifest = value

    @staticmethod
    def _architectures(data):
        magic = data[:4]
        if magic in identity.THIN:
            order, header_size = identity.THIN[magic]
            if len(data) < header_size:
                raise ValueError('Truncated Mach-O header')
            cpu, subtype = struct.unpack_from(order+'II', data, 4)
            return [identity._architecture(cpu, subtype)]
        if magic in identity.FAT:
            order, wide = identity.FAT[magic]
            if len(data) < 8:
                raise ValueError('Truncated universal Mach-O header')
            count = struct.unpack_from(order+'I', data, 4)[0]
            width = 32 if wide else 20
            if not 1 <= count <= 128 or 8 + count * width > len(data):
                raise ValueError('Unsupported universal Mach-O table')
            return [identity._architecture(*struct.unpack_from(order+'II', data, 8+i*width)) for i in range(count)]
        return []

    def inventory(self, pattern='', offset=0, limit=30, view=None):
        if not isinstance(pattern, str) or len(pattern) > 10000 or isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 or isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
            raise ValueError('Invalid inventory pattern/offset/limit')
        if self._manifest is None:
            self._scan()
        manifest = self._manifest
        expected = _key({'snapshot': manifest['snapshot'], 'pattern': pattern})
        if (view is not None and view != expected) or (offset and view is None):
            raise ValueError('Stale or missing inventory view; request offset=0 without view')
        matches = [row for row in manifest['entries'] if pattern.casefold() in row['path'].casefold()]
        items = matches[offset:offset+limit]
        return {'classification': 'computed', 'application_snapshot': manifest['snapshot'],
                'view': expected, 'items': items, 'matches': len(matches),
                'match_scope': 'recorded inventory; incomplete traversal can omit paths',
                'next_offset': offset + len(items) if offset + len(items) < len(matches) else None,
                'coverage': manifest['coverage'], 'relationships': manifest['relationships'][:30],
                'relationships_truncated': len(manifest['relationships']) > 30,
                'limitations': manifest['limitations']}

    def _component(self, component_id):
        if self._manifest is None:
            self._scan()
        if not isinstance(component_id, str):
            raise ValueError('Invalid component identity')
        matches = [row for row in self._manifest['entries'] if row['component_id'] == component_id]
        if len(matches) != 1:
            raise ValueError('Unknown/stale component identity; inventory selected root again')
        row = matches[0]
        if not row.get('capturable'):
            raise ValueError('Component cannot be captured: ' + row.get('reason', row['kind']))
        return row

    def capture(self, component_id, architecture='auto'):
        row = self._component(component_id)
        self._deadline = time.monotonic() + self.limits['seconds']
        try:
            if 'archive' in row:
                raw = self._bytes(row['archive'], self.limits['file_bytes'])
                if _digest(raw) != row['archive_sha256']:
                    raise ValueError('Archive changed since inventory; reopen inventory')
                start, size = row['offset'], row['size']
                if start > len(raw) or size > len(raw) - start:
                    raise ValueError('ASAR captured member range escapes archive')
                data = raw[start:start+size]
                declared = row.get('declared_integrity')
                if declared is not None:
                    if declared.get('status') != 'supported_sha256_unverified':
                        raise ValueError('Unsupported ASAR declared integrity: ' + declared['reason'])
                    if _digest(data) != declared['hash']:
                        raise ValueError('ASAR declared SHA256 mismatch for captured member')
            else:
                data = self._bytes(row['path'], self.limits['file_bytes'])
                if _digest(data) != row['sha256']:
                    raise ValueError('Component changed since inventory; reopen inventory')
            digest = _digest(data)
            folder = self._folder('captures', self._manifest['snapshot'], component_id)
            suffix = Path(row['path']).suffix
            suffix = suffix if len(suffix) <= 16 and suffix.replace('.', '').isalnum() else ''
            path = folder / ('input-' + digest + suffix)
            if path.is_symlink():
                raise ValueError('Immutable component capture must not be a symlink')
            if path.exists():
                if _digest(path.read_bytes()) != digest:
                    raise ValueError('Immutable component capture was modified')
            else:
                fd, temporary = tempfile.mkstemp(dir=folder)
                try:
                    with os.fdopen(fd, 'wb') as target:
                        target.write(data)
                        target.flush()
                        os.fsync(target.fileno())
                    os.chmod(temporary, 0o444)
                    os.link(temporary, path)
                finally:
                    os.unlink(temporary)
            selection = identity.select(path, architecture)
            verification = ({'status': 'matched', 'scope': 'whole_member_sha256',
                             'declaration_trust': 'untrusted_archive_metadata',
                             'authenticity_established': False, 'block_hashes_checked': False}
                            if row.get('declared_integrity') else {'status': 'not_declared'})
            return {'declared_integrity_verification': verification, 'path': str(path), 'application_snapshot': self._manifest['snapshot'],
                    'component_id': component_id, 'sha256': digest, 'selection': selection,
                    'source': row, 'classification': 'fact'}
        finally:
            self._deadline = 0

    def inspect_javascript(self, component_id, offset=0, limit=30, view=None,
                           index_cursor=None, find='', source_offset=None, source_length=2048,
                           binding_at=None, api=None):
        if (type(offset) is not int or offset < 0 or type(limit) is not int or not 1 <= limit <= 200
                or not isinstance(find, str) or len(find) > 256
                or (index_cursor is not None and (not isinstance(index_cursor, str) or len(index_cursor) > 200))
                or (source_offset is not None and (type(source_offset) is not int or source_offset < 0))
                or type(source_length) is not int or not 1 <= source_length <= 8192
                or (binding_at is not None and (type(binding_at) is not int or binding_at < 0))
                or (api is not None and (not isinstance(api,str) or not 1 <= len(api) <= 128))):
            raise ValueError('Invalid JavaScript inspection bounds')
        if api is not None and binding_at is None:
            raise ValueError('api requires binding_at from an observed exposeInMainWorld start_byte')
        if binding_at is not None and (index_cursor is not None or view is not None or offset or find or source_offset is not None):
            raise ValueError('Binding focus is a separate bounded operation; do not combine it with syntax paging/expansion or source windows')
        row = self._component(component_id)
        if row['kind'] != 'javascript':
            raise ValueError('Selected component is not supported JavaScript source')
        if row['size'] > min(self.limits['javascript_bytes'], SOURCE_LIMIT):
            raise ValueError('JavaScript component exceeds coherent-parse byte budget')
        captured = self.capture(component_id)
        if source_offset is not None:
            if index_cursor is not None or view is not None or offset or find:
                raise ValueError('Source windows do not page or expand the syntax index')
            data = Path(captured['path']).read_bytes()
            if _digest(data) != captured['sha256']:
                raise ValueError('Immutable JavaScript capture changed')
            data.decode('utf-8')
            if source_offset > len(data):
                raise ValueError('Source offset exceeds captured bytes')
            start = source_offset
            while start < len(data) and data[start] & 0xc0 == 0x80:
                start += 1
            end = min(len(data), start + source_length)
            while end > start and end < len(data) and data[end] & 0xc0 == 0x80:
                end -= 1
            if end == start and start < len(data):
                raise ValueError('source_length is too small for a UTF-8 character; request at least four bytes')
            return {'classification': 'fact', 'application_snapshot': captured['application_snapshot'],
                    'component_id': component_id, 'source_sha256': captured['sha256'],
                    'source_window': {'requested_start_byte': source_offset, 'start_byte': start, 'end_byte': end, 'text': data[start:end].decode('utf-8'),
                                      'next_source_offset': end if end < len(data) else None},
                    'limitations': ['Captured source display only; no parsing, index expansion or execution.']}
        folder = self._folder('javascript', captured['application_snapshot'], component_id,
                              syntax_digest(parser_identity()))
        if binding_at is not None:
            if binding_at >= row['size']:
                raise ValueError('binding_at exceeds captured source')
            from .js_bindings import BINDING_SCHEMA
            result = self.syntax_owner.run({'capture':captured['path'],'sha256':captured['sha256'],
                'binding_at':binding_at,'api':api},folder=folder,cancelled=self.cancelled,
                wall_seconds=min(15.0,self.limits['seconds']))
            return {**result['binding'],'application_snapshot':captured['application_snapshot'],
                    'component_id':component_id,'source_sha256':captured['sha256'],
                    'binding_identity':syntax_digest({'snapshot':captured['application_snapshot'],
                        'component':component_id,'sha256':captured['sha256'],'parser':parser_identity(),
                        'binding_schema':BINDING_SCHEMA,'binding_at':binding_at,'api':api}),
                    'parser':parser_identity(),'resource_limits':result['resource_limits']}
        return inspect_index(self.syntax_owner, captured, folder, offset=offset, limit=limit, view=view,
                             index_cursor=index_cursor, find=find, cancelled=self.cancelled,
                             wall_seconds=min(15.0, self.limits['seconds']))
