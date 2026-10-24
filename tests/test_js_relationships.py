import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from eaos.application_session import ApplicationSession
from eaos.js_relationships import project

SOURCE = b'''(()=>{const table={1(module,exports,load){const service=load(2);exports.api=service;},2(module,exports){exports.value='different-from-key';}};function load(id){const m={exports:{}};table[id](m,m.exports,load);return m.exports;}load(1)})();'''


class Relationships(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.base=Path(self.tmp.name);self.root=self.base/'App';self.root.mkdir()
        (self.root/'main.js').write_bytes(SOURCE)
        self.session=ApplicationSession(self.root,self.base/'cache');self.addCleanup(self.session.close)
        self.cid=self.session.call('inventory_application',{})['data']['items'][0]['component_id']

    def inspect(self, **args):
        return self.session.call('inspect_javascript',dict(component_id=self.cid,**args))

    def records(self, raw=SOURCE):
        focus=raw.index(b'exports.api')
        first=self.inspect(module_at=focus)
        second=self.inspect(module_at=focus,module_id='2',module_kind='assignments')
        return [first['evidence']['id'],second['evidence']['id']]

    def compose(self, ids, **args):
        return self.inspect(relationship_evidence=ids,**args)

    def test_positive_candidate_basis_context_profiles_and_reopen(self):
        ids=self.records();r=self.compose(ids)
        links=[x for x in r['data']['items'] if x['kind']=='relationship']
        self.assertEqual(len(links),1)
        self.assertEqual(links[0]['status'],'candidate_only')
        self.assertIn('Formal-to-loader',links[0]['unresolved'][0])
        self.assertEqual(r['data']['coverage']['IPC_edges_established'],0)
        profiles=r['data']['input_profiles']
        self.assertEqual(profiles[0]['profile_versions']['module_schema'],5)
        self.assertFalse(profiles[0]['scope_summary']['semantic_analysis_complete'])
        self.assertTrue(profiles[0]['original_metadata_in_saved_evidence'])
        saved=self.session.call('read_evidence',{'id':r['evidence']['id'],'limit':40000})
        full=json.loads(saved['text'])['data']['input_profiles'][0]
        self.assertTrue(full['original_profile']['module_schema']==5)
        self.assertTrue(full['original_limitations'])
        self.session.close()
        reopened=ApplicationSession(self.root,self.base/'cache');self.addCleanup(reopened.close)
        reopened.call('inventory_application',{})
        self.assertEqual(reopened.call('read_evidence',{'id':r['evidence']['id'],'limit':40000})['text'],saved['text'])

    def test_shadowing_mutation_destructuring_and_eval_refuse_lookup_candidate(self):
        variants=[
            SOURCE.replace(b'const service=load(2)',b'load=other;const service=load(2)'),
            SOURCE.replace(b'const service=load(2)',b'({load}=other);const service=load(2)'),
            SOURCE.replace(b'const service=load(2)',b'for(load of list){}const service=load(2)'),
            SOURCE.replace(b'const service=load(2)',b'arguments[2]=other;const service=load(2)'),
            SOURCE.replace(b'const service=load(2)',b'{const load=other;const service=load(2)}'),
            SOURCE.replace(b'const service=load(2)',b'const {load}=other;const service=load(2)'),
            SOURCE.replace(b'const service=load(2)',b'eval(code);const service=load(2)'),
            SOURCE.replace(b'const service=load(2)',b"(eval)('load=other');const service=load(2)"),
            SOURCE.replace(b'const service=load(2)',b'function nested(load){const service=load(2)}'),
        ]
        for i,raw in enumerate(variants):
            with self.subTest(i=i), tempfile.TemporaryDirectory() as tmp:
                root=Path(tmp)/'App';root.mkdir();(root/'main.js').write_bytes(raw)
                s=ApplicationSession(root,Path(tmp)/'cache')
                try:
                    cid=s.call('inventory_application',{})['data']['items'][0]['component_id']
                    focus=raw.index(b'exports.api')
                    a=s.call('inspect_javascript',{'component_id':cid,'module_at':focus})
                    b=s.call('inspect_javascript',{'component_id':cid,'module_at':focus,'module_id':'2','module_kind':'assignments'})
                    r=s.call('inspect_javascript',{'component_id':cid,'relationship_evidence':[a['evidence']['id'],b['evidence']['id']]})
                    self.assertFalse([x for x in r['data']['items'] if x['kind']=='relationship'])
                finally:s.close()

    def test_equal_keys_in_different_tables_and_components_do_not_join(self):
        raw=SOURCE+b";const other={2(module,exports){exports.value='other';}};"
        (self.root/'main.js').write_bytes(raw);(self.root/'second.js').write_bytes(SOURCE)
        self.session.close();self.session=ApplicationSession(self.root,self.base/'cache');self.addCleanup(self.session.close)
        inv=self.session.call('inventory_application',{})['data']['items']
        self.cid=next(x['component_id'] for x in inv if x['path']=='main.js')
        other=next(x['component_id'] for x in inv if x['path']=='second.js')
        a=self.inspect(module_at=raw.index(b'exports.api'))
        b=self.inspect(module_at=raw.index(b"exports.value='other'"),module_kind='assignments')
        c=self.session.call('inspect_javascript',{'component_id':other,'module_at':SOURCE.index(b'exports.api'),'module_id':'2','module_kind':'assignments'})
        r=self.compose([a['evidence']['id'],b['evidence']['id'],c['evidence']['id']])
        self.assertEqual(r['data']['coverage']['relationships'],0)

    def test_views_paging_checksum_stale_source_and_mode_validation(self):
        ids=self.records();first=self.compose(ids,limit=1)
        second=self.compose(ids,limit=1,offset=1,view=first['data']['view'])
        self.assertNotEqual(first['data']['items'],second['data']['items'])
        for kwargs in ({'offset':1},{'view':'bad'},{'module_at':0},{'source_offset':0}):
            with self.assertRaises(ValueError):self.compose(ids,**kwargs)
        for bad in ([ids[0],ids[0]],['../'+'a'*29]):
            with self.assertRaises(ValueError):self.compose(bad)
        with self.assertRaises(ValueError):self.compose(list(reversed(ids)),view=first['data']['view'])
        path=Path(first['evidence']['path']).parent/(ids[0]+'.json')
        original=path.read_bytes();path.write_bytes(original+b' ')
        with self.assertRaisesRegex(ValueError,'hash mismatch'):self.compose(ids)
        path.write_bytes(original)
        (self.root/'main.js').write_bytes(SOURCE+b';changed()')
        with self.assertRaises((ValueError,FileNotFoundError)):self.compose(ids)
        self.assertEqual(path.read_bytes(),original)

    def test_preserves_only_existing_narrow_preload_claim_and_no_equal_channel_edge(self):
        raw=b"const {contextBridge,ipcRenderer}=require('electron');contextBridge.exposeInMainWorld('Demo',{get(){return ipcRenderer.sendSync('GET')}});obj.on('GET',f)"
        (self.root/'main.js').write_bytes(raw)
        self.session.close();self.session=ApplicationSession(self.root,self.base/'cache');self.addCleanup(self.session.close)
        self.cid=self.session.call('inventory_application',{})['data']['items'][0]['component_id']
        a=self.inspect(binding_at=raw.index(b'contextBridge.expose'),api='get')
        b=self.inspect(find='GET')
        r=self.compose([a['evidence']['id'],b['evidence']['id']])
        links=[x for x in r['data']['items'] if x['kind']=='relationship']
        self.assertEqual(len(links),3)
        self.assertTrue(all(x['status']=='preserved_narrow_binding' for x in links))
        self.assertEqual(r['data']['coverage']['IPC_edges_established'],0)
        self.assertTrue(any(x.get('accepted_narrow_binding') for x in r['data']['items']))

    def test_projection_budgets_cancel_and_conflicting_context(self):
        ids=self.records()
        evidence=self.session.application_evidence
        records=[json.loads(evidence.read(i,limit=40000)['text']) for i in ids]
        capture=self.session.application.capture(self.cid)
        contexts={self.cid:{'component_id':self.cid,'application_snapshot':capture['application_snapshot'],
                            'sha256':capture['sha256'],'size':len(SOURCE)}}
        r=project(records,contexts,self.cid,max_nodes=1)
        self.assertGreater(r['coverage']['omitted'],0)
        self.assertEqual(r['coverage']['stopping_reason'],'node_budget')
        r=project(records,contexts,self.cid,max_links=0)
        self.assertEqual(r['coverage']['relationships'],0)
        self.assertEqual(r['coverage']['stopping_reason'],'relationship_budget')
        with self.assertRaises(InterruptedError):project(records,contexts,self.cid,cancelled=lambda:True)
        for key in ('source_sha256','application_snapshot','table_identity'):
            bad=copy.deepcopy(records);bad[0]['data'][key]='wrong'
            with self.assertRaises(ValueError):project(bad,contexts,self.cid)
        bad=copy.deepcopy(records);bad[0]['data']['module_schema']=4
        with self.assertRaisesRegex(ValueError,'table identity'):project(bad,contexts,self.cid)

    def test_mutated_preload_receiver_never_promotes_a_binding(self):
        raw=b"const {contextBridge,ipcRenderer}=require('electron');ipcRenderer.sendSync=other;contextBridge.exposeInMainWorld('Demo',{get(){return ipcRenderer.sendSync('GET')}})"
        (self.root/'main.js').write_bytes(raw)
        self.session.close();self.session=ApplicationSession(self.root,self.base/'cache');self.addCleanup(self.session.close)
        self.cid=self.session.call('inventory_application',{})['data']['items'][0]['component_id']
        a=self.inspect(binding_at=raw.index(b'contextBridge.expose'),api='get')
        r=self.compose([a['evidence']['id']])
        self.assertEqual(r['data']['coverage']['IPC_edges_established'],0)
        self.assertFalse(any(x.get('accepted_narrow_binding') for x in r['data']['items']))
        self.assertFalse([x for x in r['data']['items'] if x['kind']=='relationship'])

    def test_byte_budget_and_nested_projection_refusals_preserve_originals(self):
        from unittest.mock import patch
        ids=self.records();record=self.compose(ids)
        before={p.name:p.read_bytes() for p in self.session.application_evidence.directory.iterdir() if p.is_file()}
        with patch('eaos.js_relationships.RECORD_BYTES',1):
            with self.assertRaisesRegex(ValueError,'byte budget'):self.compose(ids)
        with self.assertRaisesRegex(ValueError,'original inspection'):
            self.compose([record['evidence']['id']])
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.session.application_evidence.directory.iterdir() if p.is_file()})

    def test_duplicate_target_headers_never_create_a_lookup_candidate(self):
        raw=SOURCE.replace(b'};function load',b",2(module,exports){exports.value='replacement';}};function load")
        (self.root/'main.js').write_bytes(raw)
        self.session.close();self.session=ApplicationSession(self.root,self.base/'cache');self.addCleanup(self.session.close)
        self.cid=self.session.call('inventory_application',{})['data']['items'][0]['component_id']
        first=self.inspect(module_at=raw.index(b'exports.api'))
        second=self.inspect(module_at=raw.index(b"exports.value='different"),module_kind='assignments')
        result=self.compose([first['evidence']['id'],second['evidence']['id']])
        self.assertEqual(result['data']['coverage']['relationships'],0)

    def test_cancel_during_evidence_read_refuses_conflicting_work_and_keeps_records(self):
        from unittest.mock import patch
        import threading
        from eaos.evidence import Evidence
        ids=self.records();started=threading.Event();release=threading.Event();errors=[]
        original=Evidence.read
        def blocked(owner,*args,**kwargs):
            started.set();release.wait(2);return original(owner,*args,**kwargs)
        def run():
            try:self.session.call('inspect_javascript',{'component_id':self.cid,'relationship_evidence':ids},request_id=9)
            except Exception as exc:errors.append(exc)
        before={p.name:p.read_bytes() for p in self.session.application_evidence.directory.iterdir() if p.is_file()}
        with patch.object(Evidence,'read',blocked):
            worker=threading.Thread(target=run);worker.start()
            try:
                self.assertTrue(started.wait(1))
                with self.assertRaisesRegex(RuntimeError,'active'):
                    self.session.call('select_component',{'component_id':self.cid})
                self.session.cancel_request(9)
                self.assertEqual(self.session.call('open_program',{})['data']['analysis']['state'],'working')
            finally:release.set();worker.join(3)
        self.assertFalse(worker.is_alive());self.assertIsInstance(errors[0],InterruptedError)
        self.assertEqual(before,{p.name:p.read_bytes() for p in self.session.application_evidence.directory.iterdir() if p.is_file()})

    def test_adaptive_pages_keep_node_ids_and_do_not_skip_items(self):
        ids=self.records();evidence=self.session.application_evidence
        originals=[json.loads(evidence.read(i,limit=40000)['text']) for i in ids]
        records=[]
        for i in range(11):
            r=copy.deepcopy(originals[0]);r['id']=f'{i:032x}';records.append(r)
        records.append(originals[1])
        capture=self.session.application.capture(self.cid)
        contexts={self.cid:{'component_id':self.cid,'application_snapshot':capture['application_snapshot'],
                            'sha256':capture['sha256'],'size':len(SOURCE)}}
        seen=[];kwargs={}
        while True:
            r=project(records,contexts,self.cid,limit=200,**kwargs)
            self.assertLessEqual(r['page_item_bytes'],7000)
            self.assertTrue(all('node_id' in x or 'from' in x for x in r['items']))
            seen+=r['items']
            if r['next_offset'] is None:break
            kwargs={'view':r['view'],'offset':r['next_offset']}
        self.assertEqual(len(seen),r['matches'])
        self.assertEqual(len({x.get('node_id',(x.get('from'),x.get('to'))) for x in seen}),len(seen))
