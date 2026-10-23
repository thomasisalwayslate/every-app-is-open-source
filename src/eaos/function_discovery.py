"""Bounded derived name index inside an existing quick-analysis profile.

SQLite is from Python's standard library. Candidate rows and their high-water
mark commit together; program readiness/revisions remain owned by quick.py.
Tokens are typed state identifiers, never paths, SQL or executable expressions.
"""
from __future__ import annotations

import hashlib
import heapq
import json
import math
import re
import sqlite3
from time import monotonic
import uuid

from . import quick

SCHEMA_VERSION = 1
BATCH_BYTES = 8 * 1024 * 1024
TOTAL_BYTES = 256 * 1024 * 1024  # Payload accounting; SQLite overhead is additional.
QUERY_SECONDS = 2
MAX_NAME_CHARS = 4096
MAX_ALIAS_BYTES = 16384
RECOVERY = "Restart search(kind='functions', offset=0) without view/index_cursor to obtain current cursors."
TOKEN = re.compile(r'(fi1|fv1):([0-9a-f]{32}):([0-9a-f]{1,16}):([0-9a-f]{32}):([0-9a-f]{1,16})(?::([0-9a-f]{32}))?')


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def context(backend):
    return hashlib.sha256(canonical({'profile': backend.identity, 'discovery_schema': SCHEMA_VERSION}).encode()).hexdigest()[:32]


def decode(backend, token, kind):
    match = TOKEN.fullmatch(token)
    if not match or match[1] != kind or bool(match[6]) != (kind == 'fv1'):
        raise ValueError('Malformed discovery cursor. '+RECOVERY)
    if match[2] != context(backend):
        raise ValueError('Cursor belongs to another input, architecture, profile or index schema. '+RECOVERY)
    if int(match[3], 16) != backend.revision:
        raise ValueError('Stale cursor: analysis revision changed. '+RECOVERY)
    return {'generation':match[4], 'position':int(match[5],16), 'query':match[6]}


def row_key(row):
    address = row['address']
    return (address.split(':')[0] if ':' in address else '', int(address.split(':')[-1],16))


class Index:
    def __init__(self, backend, supplied=False):
        self.backend = backend
        self.path = backend.directory / 'function-index-v1.sqlite'
        self.context = context(backend)
        self.db = None
        if self.path.is_symlink():
            raise RuntimeError('Discovery index is a symlink; preserved without following it.')
        exists = self.path.exists()
        if supplied and not exists:
            raise ValueError('Discovery state is unavailable. '+RECOVERY)
        try:
            self.db = sqlite3.connect(self.path, timeout=0, isolation_level=None)
            self.db.execute('PRAGMA trusted_schema=OFF')
            self.db.execute('PRAGMA cache_size=-4096')
            self.db.execute('PRAGMA temp_store=MEMORY')
            if not exists:
                self.db.execute('BEGIN IMMEDIATE')
                self.db.execute('CREATE TABLE state (id INTEGER PRIMARY KEY CHECK(id=1), context TEXT, revision INTEGER, generation TEXT, position INTEGER, initialized INTEGER, reason TEXT, bytes INTEGER, batch_start INTEGER, limits TEXT)')
                self.db.execute('CREATE TABLE candidates (position INTEGER PRIMARY KEY CHECK(position>=0), address_key TEXT UNIQUE, names TEXT, payload TEXT, shadowed INTEGER, bytes INTEGER, checksum TEXT)')
                self.db.execute('CREATE INDEX candidate_address ON candidates(address_key)')
                self.db.execute(f'PRAGMA user_version={SCHEMA_VERSION}')
                self.db.execute('INSERT INTO state VALUES (1,?,?,?,0,0,NULL,0,0,NULL)', (self.context,backend.revision,uuid.uuid4().hex))
                self.db.execute('COMMIT')
            if self.db.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION:
                raise ValueError('Incompatible discovery schema')
            self.refresh()
            count,low,high,used = self.db.execute('SELECT count(*), min(position), max(position), coalesce(sum(bytes),0) FROM candidates').fetchone()
            available = len(backend.quick_metadata['function_starts'])
            if (self.state['context'] != self.context or not 0 <= self.state['position'] <= available or
                    count != self.state['position'] or (count and (low != 0 or high != count-1)) or
                    not 0 <= self.state['bytes'] <= TOTAL_BYTES or used != self.state['bytes'] or
                    self.state['initialized'] not in (0,1) or
                    not re.fullmatch('[0-9a-f]{32}',self.state['generation']) or
                    not 0 <= self.state['batch_start'] <= self.state['position'] or
                    (not self.state['initialized'] and self.state['position']) or
                    (self.state['initialized'] and self.state['reason'] not in
                     ('complete','candidate_limit','time_limit','byte_limit','storage_limit'))):
                raise ValueError('Invalid discovery state/counts')
            if self.state['initialized']:
                limits=json.loads(self.state['limits'])
                if (set(limits) != {'candidates','seconds','bytes'} or
                        any(type(value) not in (int,float) or not math.isfinite(value) or value<0 for value in limits.values()) or
                        (self.state['position']==available) != (self.state['reason']=='complete')):
                    raise ValueError('Invalid discovery batch provenance')
            if self.state['revision'] != backend.revision:
                if supplied:
                    raise ValueError('Stale discovery revision')
                # Verified program revision is authoritative. This is a derived
                # view invalidation, not a competing program-state migration.
                self.db.execute('BEGIN IMMEDIATE')
                self.db.execute('DELETE FROM candidates')
                self.db.execute('UPDATE state SET revision=?, generation=?, position=0, initialized=0, reason=NULL, bytes=0, batch_start=0, limits=NULL WHERE id=1', (backend.revision,uuid.uuid4().hex))
                self.db.execute('COMMIT')
                self.refresh()
            self.db.execute('CREATE TEMP TABLE covered (address_key TEXT PRIMARY KEY)')
        except Exception as error:
            if self.db is not None:
                if self.db.in_transaction:self.db.rollback()
                self.close()
            raise RuntimeError('Discovery cache incomplete, corrupt or incompatible; preserved. Close the session and preserve/move only function-index-v1.sqlite and its journal aside before regenerating. '+str(error)) from error

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None

    def refresh(self):
        row = self.db.execute('SELECT context, revision, generation, position, initialized, reason, bytes, batch_start, limits FROM state WHERE id=1').fetchone()
        if row is None:raise ValueError('Missing discovery state')
        self.state = dict(zip(('context','revision','generation','position','initialized','reason','bytes','batch_start','limits'),row))

    def token(self, kind='fi1', query=None):
        s = self.state
        value = f"{kind}:{self.context}:{self.backend.revision:x}:{s['generation']}:{s['position']:x}"
        return value+(':'+query if query is not None else '')

    def validate(self, value):
        if value['generation'] != self.state['generation'] or value['position'] != self.state['position']:
            raise ValueError('Stale cursor: candidate index expanded or reset. '+RECOVERY)

    def cancelled(self):
        monitor = self.backend.monitor
        return monitor is not None and monitor.isCancelled()

    def candidate(self, position, deadline):
        b = self.backend
        number = b.quick_metadata['function_starts'][position]
        at = b.program.getAddressFactory().getDefaultAddressSpace().getAddress(number)
        symbols = b.program.getSymbolTable()
        primary = symbols.getPrimarySymbol(at)
        name = str(primary.getName()) if primary is not None else 'FUN_'+str(at)
        qualified = str(primary.getName(True)) if primary is not None else name
        row = {'address':str(at),'name':name[:MAX_NAME_CHARS], 'source':'function_start_candidate',
               'analysis':{'state':'not_prepared'}}
        if len(name)>MAX_NAME_CHARS:row['name_truncated']=True
        if qualified != name:
            row['qualified_name']=qualified[:MAX_NAME_CHARS]
            if len(qualified)>MAX_NAME_CHARS:row['qualified_name_truncated']=True
        shadowed = b.program.getFunctionManager().getFunctionAt(at) is not None
        aliases = set()
        if not shadowed:
            alias_bytes = 0
            for i,symbol in enumerate(symbols.getSymbols(at)):
                if self.cancelled():raise RuntimeError('Discovery cancelled; current batch rolled back.')
                if monotonic()>=deadline:raise TimeoutError('time_limit')
                if i>=128:
                    row['aliases_truncated']=True;break
                for alias in (str(symbol.getName()),str(symbol.getName(True))):
                    if alias in (name,qualified) or alias in aliases:continue
                    clipped=alias[:MAX_NAME_CHARS]
                    cost=len(clipped.encode())
                    if alias_bytes+cost>MAX_ALIAS_BYTES:
                        row['aliases_truncated']=True;break
                    aliases.add(clipped);alias_bytes+=cost
                    if clipped != alias:row['aliases_truncated']=True
                if row.get('aliases_truncated'):break
        if aliases:row['aliases']=sorted(aliases)
        payload=canonical(row)
        names=' '.join([row['name'],row.get('qualified_name',''),*row.get('aliases',[])]).casefold()
        size=len(payload.encode())+len(names.encode())
        checksum=hashlib.sha256(canonical([position,f'{number:016x}',names,payload,int(shadowed),size]).encode()).hexdigest()
        return (position,f'{number:016x}',names,payload,int(shadowed),size,checksum)

    def expand(self):
        """One atomic prefix extension. Hard session deadlines include commit IO."""
        available=len(self.backend.quick_metadata['function_starts'])
        start=position=self.state['position'];used=0;reason='complete'
        limits={'candidates':quick.MAX_NAME_CANDIDATES,'seconds':quick.NAME_INDEX_SECONDS,'bytes':BATCH_BYTES}
        deadline=monotonic()+quick.NAME_INDEX_SECONDS
        self.backend._report_stage('indexing_function_candidates')
        self.db.execute('BEGIN IMMEDIATE')
        try:
            while position<available:
                if self.cancelled():raise RuntimeError('Discovery cancelled; current batch rolled back.')
                if position-start>=quick.MAX_NAME_CANDIDATES:reason='candidate_limit';break
                if monotonic()>=deadline:reason='time_limit';break
                try:row=self.candidate(position,deadline)
                except TimeoutError:reason='time_limit';break
                if self.state['bytes']+used+row[5]>TOTAL_BYTES:reason='storage_limit';break
                if used+row[5]>BATCH_BYTES:reason='byte_limit';break
                self.db.execute('INSERT INTO candidates VALUES (?,?,?,?,?,?,?)',row)
                used+=row[5];position+=1
            if self.cancelled():raise RuntimeError('Discovery cancelled; current batch rolled back.')
            self.db.execute('UPDATE state SET position=?, initialized=1, reason=?, bytes=bytes+?, batch_start=?, limits=? WHERE id=1',(position,reason,used,start,canonical(limits)))
            self.db.execute('COMMIT')
        except BaseException:
            if self.db.in_transaction:self.db.rollback()
            raise
        self.refresh()

    def coverage(self):
        s=self.state;available=len(self.backend.quick_metadata['function_starts'])
        complete=s['position']==available
        can_continue=not complete and s['reason']!='storage_limit'
        return {'candidates_indexed':s['position'],'candidates_available':available,
                'index_complete':complete,'truncated':not complete,'reason':s['reason'],
                'batch_start':s['batch_start'],'batch_end':s['position'],
                'can_continue':can_continue,'next_index_cursor':self.token() if can_continue else None,
                'scope':'parsed function-start candidates only; not complete symbol recovery',
                'batch_limits':json.loads(s['limits']) if s['limits'] is not None else None}

    def matches(self, pattern, native_rows, offset, limit, view=None):
        native_rows.sort(key=row_key)
        query=hashlib.sha256(canonical([pattern,[[r['address'],r['name'],r.get('qualified_name'),r.get('aliases')]for r in native_rows]]).encode()).hexdigest()[:32]
        if view is not None and view['query'] != query:
            raise ValueError('Result view belongs to another query or changed metadata. '+RECOVERY)
        deadline=monotonic()+QUERY_SECONDS
        def interrupted():return int(self.cancelled() or monotonic()>=deadline)
        self.db.set_progress_handler(interrupted,1000)
        try:
            if interrupted():
                raise RuntimeError('Candidate query deadline/cancellation; committed index preserved. '+RECOVERY)
            # Prefer matching metadata rows at the same internal entry while
            # preserving candidate alias searches when a Go name doesn't match.
            self.db.execute('DELETE FROM covered')
            def covered_rows():
                for i,row in enumerate(native_rows):
                    if i%256==0 and interrupted():
                        raise RuntimeError('Candidate query deadline/cancellation; committed index preserved. '+RECOVERY)
                    if ':'not in row['address']:
                        yield (f"{int(row['address'],16):016x}",)
            self.db.executemany('INSERT OR IGNORE INTO covered VALUES (?)',covered_rows())
            # Validate the entire committed prefix before returning even an empty
            # page. Filtering first can hide a corrupt search key or shadow flag,
            # and stopping at a page boundary can conceal a corrupt later row.
            cursor=self.db.execute('SELECT position,address_key,names,payload,shadowed,bytes,checksum, '
                'EXISTS (SELECT 1 FROM covered WHERE covered.address_key=candidates.address_key) '
                'FROM candidates ORDER BY address_key')
            def candidate_rows():
                for scanned,(pos,key,names,payload,shadowed,size,checksum,covered) in enumerate(cursor):
                    if scanned%256==0 and interrupted():
                        raise RuntimeError('Candidate integrity/query deadline/cancellation; committed index preserved. '+RECOVERY)
                    actual=hashlib.sha256(canonical([pos,key,names,payload,shadowed,size]).encode()).hexdigest()
                    if (actual != checksum or type(pos) is not int or not 0<=pos<self.state['position'] or
                            key != f"{self.backend.quick_metadata['function_starts'][pos]:016x}" or
                            shadowed not in (0,1) or size != len(payload.encode())+len(names.encode())):
                        raise RuntimeError('Discovery row corrupt; cache preserved, no completeness claim.')
                    if not shadowed and not covered and pattern in names:
                        yield json.loads(payload)
            merged=heapq.merge(native_rows,candidate_rows(),key=row_key)
            page=[];count=0
            for index,row in enumerate(merged):
                if index%256==0 and interrupted():raise RuntimeError('Candidate query deadline/cancellation; refine pattern. Committed index preserved.')
                count=index+1
                if offset<=index<offset+limit:page.append(row)
            return page,count,self.token('fv1',query)
        except sqlite3.Error as error:
            raise RuntimeError('Candidate query failed/deadline/cancellation; committed index preserved. Refine pattern or restart session. '+str(error)) from error
        finally:self.db.set_progress_handler(None,0)


def open_index(backend,index_cursor=None,view=None):
    continuation=decode(backend,index_cursor,'fi1') if index_cursor is not None else None
    page=decode(backend,view,'fv1') if view is not None else None
    if backend.discovery_index is None:
        backend.discovery_index=Index(backend,supplied=continuation is not None or page is not None)
    index=backend.discovery_index
    for token in (continuation,page):
        if token is not None:index.validate(token)
    if continuation is not None:
        if not index.coverage()['can_continue']:
            raise ValueError('No further indexing is possible; inspect coverage. '+RECOVERY)
        index.expand()
    elif not index.state['initialized']:
        if page is not None:
            raise ValueError('No committed result view is available. '+RECOVERY)
        index.expand()
    backend.quick_name_coverage=index.coverage()
    return index,page
