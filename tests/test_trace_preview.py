"""Preview-only regressions: full immutable trace data stays in evidence."""
from copy import deepcopy
import json
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

from eaos.backend import Backend
from eaos.tracing import trace


class TracePreview(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        target=Path(self.temp.name)/'fixture';target.write_bytes(b'portable preview fixture')
        self.backend=Backend(str(target))
        self.backend.program=SimpleNamespace(getFunctionManager=lambda:SimpleNamespace(getFunctionContaining=lambda _:None),
            getLanguageID=lambda:'portable-fixture',getCompilerSpec=lambda:SimpleNamespace(getCompilerSpecID=lambda:'fixture'))
        self.backend.address=lambda value:value
        self.backend._load=lambda:None
        self.addCleanup(self.close)

    def close(self):
        self.backend.program=None
        self.backend.close()

    def record(self,identifier):
        pages=[];offset=0
        while True:
            result=self.backend.read_evidence(identifier,offset=offset,limit=40000)
            pages.append(result['text'])
            if result['next_offset'] is None:return json.loads(''.join(pages))
            offset=result['next_offset']

    def test_large_preview_retains_full_graph_and_per_node_assertions(self):
        data={'start':'100','direction':'callees','classification':'computed',
              'nodes':[{'address':f'{256+i:x}','name':'n'*1000,'aliases':['alias'*1000],
                        'depth':0,'relationships':{'enumeration_reported_complete':False,
                        'scope':'known instruction/reference edges only','runtime_dispatch_established':False}}for i in range(32)],
              'edges':[{'source':'100','target':f'{257+i:x}','call_site':f'{4096+i:x}','kind':'direct_call'}for i in range(128)],
              'frontier':[{'address':f'{257+i:x}','reason':'unresolved '+'x'*900,'depth':1}for i in range(64)],
              'coverage':{'traversal_complete':False,'enumerated_relationships_complete':False,'stopping_reason':'node_limit'}}
        original=deepcopy(data)
        with patch('eaos.tracing.trace',return_value=data):result=self.backend.trace_calls('100')
        preview=result['data']
        self.assertLessEqual(len(json.dumps(preview,ensure_ascii=False)),12300)
        self.assertTrue(preview['preview_truncated'])
        self.assertEqual((preview['nodes_total'],preview['edges_total'],preview['frontier_total']),(32,128,64))
        self.assertIn('read_evidence',preview['next'])
        self.assertFalse(preview['nodes'][0]['relationships']['enumeration_reported_complete'])
        self.assertNotIn('aliases',preview['nodes'][0])
        self.assertEqual(data,original)
        self.assertEqual(self.record(result['evidence']['id'])['data'],original)

    def test_missing_enumeration_assertion_survives_preview_and_evidence(self):
        data=trace('100',lambda *args:{'node':{'address':'100'},'edges':[]})
        with patch('eaos.tracing.trace',return_value=data):result=self.backend.trace_calls('100')
        node=result['data']['nodes'][0]
        self.assertIsNone(node['relationships']['enumeration_reported_complete'])
        self.assertFalse(result['data']['coverage']['traversal_complete'])
        saved=self.record(result['evidence']['id'])['data']
        self.assertEqual(saved['nodes'][0]['relationships'],node['relationships'])
