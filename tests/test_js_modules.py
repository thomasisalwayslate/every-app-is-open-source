import json
from pathlib import Path
import tempfile
import unittest
from eaos.application_session import ApplicationSession
from eaos.js_modules import inspect_module

SOURCE=b'''(()=>{const table={1(module,exports,load){
const api=load(2);class Database extends Base{handler(){api.get('/accounts');api.on('signal',f)}}
exports.service=new Database();
},2(module,exports){exports.label='other';},3(module){throw new Error('never execute');}}})();'''
FOCUS=SOURCE.index(b'api.get')


class SelectedModules(unittest.TestCase):
    def test_selected_body_and_headers_are_separate_syntax_scopes(self):
        result=inspect_module(SOURCE,FOCUS)
        self.assertEqual(result['module_scope']['candidate_id'],'1')
        row=next(x for x in result['items'] if x['source_name']=='api')
        self.assertEqual(row['literal_call_argument'],'2')
        self.assertIn('unresolved',row['relationship'])
        self.assertTrue(result['scope_coverage']['selected_syntax_scan_complete'])
        self.assertEqual(result['scope_coverage']['unselected_bodies_examined'],0)
        self.assertFalse(result['scope_coverage']['ancestor_bindings_indexed'])
        other=inspect_module(SOURCE,FOCUS,module_id='2',kind='assignments')
        self.assertEqual(other['module_scope']['candidate_id'],'2')
        self.assertEqual(other['items'][0]['target_source'],'exports.label')
        self.assertNotIn('Database',json.dumps(other['items']))

    def test_map_get_and_database_names_do_not_become_product_roles(self):
        calls=inspect_module(SOURCE,FOCUS,kind='calls')
        get=next(x for x in calls['items'] if x['source_name']=='get')
        self.assertEqual(get['argument_sources'],["'/accounts'"])
        self.assertEqual(get['binding_status'],'unresolved_syntax_only')
        self.assertNotIn('network',json.dumps(calls['items']).lower())
        functions=inspect_module(SOURCE,FOCUS,kind='functions')
        self.assertTrue(any(x['source_name']=='Database' for x in functions['items']))
        self.assertNotIn('sqlite',json.dumps(functions['items']).lower())
        self.assertFalse(functions['scope_coverage']['semantic_analysis_complete'])

    def test_views_are_bound_to_scope_query_and_exact_bounded_facts(self):
        first=inspect_module(SOURCE,FOCUS,kind='calls',limit=1)
        second=inspect_module(SOURCE,FOCUS,kind='calls',limit=1,offset=1,view=first['view'])
        self.assertNotEqual(first['items'],second['items'])
        for args in ({'kind':'functions','view':first['view']},
                     {'module_id':'2','kind':'calls','view':first['view']},
                     {'kind':'calls','offset':1}):
            with self.assertRaisesRegex(ValueError,'view'):inspect_module(SOURCE,FOCUS,**args)

    def test_identical_source_in_other_component_has_a_different_view(self):
        a=inspect_module(SOURCE,FOCUS,namespace_context={'component_id':'first','application_snapshot':'app'})
        b=inspect_module(SOURCE,FOCUS,namespace_context={'component_id':'second','application_snapshot':'app'})
        self.assertNotEqual(a['view'],b['view'])
        with self.assertRaisesRegex(ValueError,'view'):
            inspect_module(SOURCE,FOCUS,view=a['view'],namespace_context={'component_id':'second','application_snapshot':'app'})

    def test_node_time_header_limits_and_duplicate_ids_are_explicit(self):
        for kwargs,reason in [({'max_nodes':1},'node_budget'),({'max_seconds':0},'time_budget')]:
            result=inspect_module(SOURCE,FOCUS,**kwargs)
            self.assertFalse(result['scope_coverage']['selected_syntax_scan_complete'])
            actual=result['scope_coverage']['stopping_reason']
            self.assertIn(actual,('node_budget','pending_node_budget') if reason=='node_budget' else ('time_budget',))
        with self.assertRaisesRegex(ValueError,'coverage may be incomplete'):
            inspect_module(SOURCE,FOCUS,module_id='2',header_limit=1)
        duplicate=SOURCE.replace(b"},3(module)",b"},2(module)")
        with self.assertRaisesRegex(ValueError,'Duplicate'):inspect_module(duplicate,FOCUS,module_id='2')
        with self.assertRaises(ValueError):inspect_module(SOURCE,len(SOURCE))
        with self.assertRaisesRegex(ValueError,'No enclosing'):inspect_module(b'let x=1',2)

    def test_original_utf8_ranges_and_byte_focus(self):
        raw=SOURCE.replace(b"exports.service",'// 日本語\r\nexports.service'.encode())
        result=inspect_module(raw,raw.index(b'api.get'),kind='assignments')
        row=result['items'][0]
        self.assertEqual(raw[row['start_byte']:row['end_byte']],b'exports.service=new Database()')
        self.assertEqual(row['line'],raw[:row['start_byte']].count(b'\n')+1)

    def test_owned_session_evidence_and_explicit_other_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);root=base/'Fixture.app';root.mkdir();(root/'main.js').write_bytes(SOURCE)
            session=ApplicationSession(root,base/'cache')
            try:
                component=session.call('inventory_application',{})['data']['items'][0]['component_id']
                row=session.call('inspect_javascript',{'component_id':component,'find':'signal'})['data']['observations'][0]
                result=session.call('inspect_javascript',{'component_id':component,'module_at':row['start_byte']})
                self.assertEqual(result['data']['module_scope']['candidate_id'],'1')
                target=session.call('inspect_javascript',{'component_id':component,'module_at':row['start_byte'],'module_id':'2','module_kind':'assignments'})
                self.assertEqual(target['data']['items'][0]['source_name'],'label')
                record=session.call('read_evidence',{'id':result['evidence']['id'],'limit':40000})
                with self.assertRaises(ValueError):session.call('inspect_javascript',{'component_id':component,'module_id':'2'})
                with self.assertRaises(ValueError):session.call('inspect_javascript',{'component_id':component,'module_at':row['start_byte'],'binding_at':row['start_byte']})
            finally:session.close()
            reopened=ApplicationSession(root,base/'cache')
            try:
                reopened.call('inventory_application',{})
                self.assertEqual(reopened.call('read_evidence',{'id':result['evidence']['id'],'limit':40000})['text'],record['text'])
            finally:reopened.close()
            self.assertEqual((root/'main.js').read_bytes(),SOURCE)

    def test_ancestor_skeleton_preserves_dispatcher_spans_and_omits_table(self):
        raw=b"(()=>{const table={1(m,e,l){const hidden='secret';e.api=l(2);},2(m){m.exports=require('electron')}};const cache={};function load(id){if(cache[id])return cache[id].exports;const m=cache[id]={exports:{}};table[id](m,m.exports,load);return m.exports;}load(1)})();"
        focus=raw.index(b'e.api')
        result=inspect_module(raw,focus,kind='ancestors')
        cov=result['scope_coverage']
        self.assertTrue(cov['ancestor_syntax_scan_complete'])
        self.assertIsNone(cov['selected_syntax_scan_complete'])
        self.assertFalse(cov['ancestor_bindings_indexed'])
        self.assertEqual(cov['omitted_scopes'][0]['entries_available'],2)
        self.assertNotIn('hidden',[r.get('source_name') for r in result['items']])
        call=next(r for r in result['items'] if r.get('callee_source')=='table[id]')
        self.assertEqual(raw[call['start_byte']:call['end_byte']],b'table[id](m,m.exports,load)')
        function=next(r for r in result['items'] if r.get('function_kind')=='function_declaration')
        self.assertEqual(function['parameters'],['id'])
        self.assertTrue(all(r['binding_status']=='unresolved_syntax_only' for r in result['items']))
        self.assertEqual(inspect_module(raw,focus,kind='ancestors',max_nodes=1)['scope_coverage']['stopping_reason'],'pending_node_budget')

    def test_bounded_previews_do_not_hide_argument_or_source_omissions(self):
        raw=b"(()=>{const t={1(m,e,l){const long='"+b'x'*300+b"';l(1,2,3,4);}}})();"
        r=inspect_module(raw,raw.index(b'l(1'),kind='declarations')
        self.assertTrue(r['items'][0]['initializer_source_omitted'])
        r=inspect_module(raw,raw.index(b'l(1'),kind='calls')
        self.assertTrue(r['items'][0]['arguments_truncated'])
        self.assertEqual(r['items'][0]['argument_count'],4)

    def test_mutation_dynamic_loading_and_inheritance_remain_source_only(self):
        raw=b"(()=>{const t={1(m,e,l){class Service extends imported.Base{constructor(){super();native.on('channel',(...args)=>this.emit('channel',...args))}};e.service=new Service;},2(m){m.exports=require('electron')}};function l(id){const m={exports:{}};t[id](m,m.exports,l);return m.exports;}l.m=t;l.m[1]=replacement;const cache={};cache[id]=l(1)})();"
        focus=raw.index(b'native.on')
        calls=inspect_module(raw,focus,kind='calls')
        self.assertTrue(all(x['binding_status']=='unresolved_syntax_only' for x in calls['items']))
        self.assertFalse(calls['scope_coverage']['whole_program_receiver_integrity'])
        ancestors=inspect_module(raw,focus,kind='ancestors')
        self.assertTrue(ancestors['scope_coverage']['ancestor_syntax_scan_complete'])
        self.assertFalse(ancestors['scope_coverage']['semantic_analysis_complete'])
        self.assertEqual(ancestors['scope_coverage']['unselected_bodies_examined'],0)
        self.assertTrue(any(x.get('target_source')=='l.m' for x in ancestors['items']))
        self.assertFalse(ancestors['scope_coverage']['ancestor_bindings_indexed'])

    def test_public_contract_rejects_incompatible_modes_and_bounds(self):
        from eaos.contracts import validate_arguments,APPLICATION_TOOLS,TOOLS
        self.assertEqual(len(TOOLS+APPLICATION_TOOLS),11)
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)/'app';root.mkdir();(root/'main.js').write_bytes(SOURCE)
            s=ApplicationSession(root,Path(tmp)/'cache')
            try:
                cid=s.call('inventory_application',{})['data']['items'][0]['component_id']
                for bad in ({'module_at':True},{'module_at':-1},{'module_kind':'exports'},
                            {'module_at':FOCUS,'index_cursor':'bad'},
                            {'module_at':FOCUS,'source_offset':0},{'module_at':FOCUS,'api':'name'},
                            {'module_at':FOCUS,'offset':1},{'module_at':len(SOURCE)},
                            {'module_at':FOCUS,'module_id':'../../arbitrary-file'}):
                    with self.assertRaises((ValueError,RuntimeError)):s.call('inspect_javascript',dict(component_id=cid,**bad))
                validate_arguments('inspect_javascript',{'component_id':cid,'module_at':FOCUS,'module_kind':'ancestors'})
            finally:s.close()
