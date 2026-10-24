import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from eaos.application_session import ApplicationSession
from eaos.js_bindings import inspect_binding, Slice


def inspect(source, api='read'):
    raw=source.encode()
    # Tests select an offset found in the fixture, not a production target oracle.
    marker=raw.index(b'.exposeInMainWorld')
    start=raw.rfind(b';',0,marker)+1
    while raw[start:start+1] in (b' ',b'\n'):start+=1
    return inspect_binding(raw,start,api)


def direct(setup="const e=require('electron');", call="e.ipcRenderer.sendSync('read')", tail=''):
    return setup+"e.contextBridge.exposeInMainWorld('Sample',{read:()=>"+call+"});"+tail


def webpack(table='table',cache='cache',loader='load',identifier='61'):
    return "(()=>{var "+table+"={"+identifier+"(mod){mod.exports=require('electron')}},"+cache+"={};"+"function "+loader+"(id){var cached="+cache+"[id];if(void 0!==cached)return cached.exports;var mod="+cache+"[id]={exports:{}};return "+table+"[id](mod,mod.exports,"+loader+"),mod.exports;}const e="+loader+'('+identifier+");e.contextBridge.exposeInMainWorld('Sample',{read:()=>e.ipcRenderer.sendSync('read')});})();"


class Bindings(unittest.TestCase):
    def test_real_import_origin_and_literal_channel_with_locations(self):
        source=direct()
        result=inspect(source)
        self.assertEqual(result['callee_origin'],['module','electron','contextBridge','exposeInMainWorld'])
        self.assertEqual(result['namespace'],'Sample')
        call=result['selected_api']['ipc_calls'][0]
        self.assertEqual(call['origin'],['module','electron','ipcRenderer','sendSync'])
        self.assertEqual(call['channel'],'read')
        self.assertEqual(source.encode()[call['start_byte']:call['end_byte']],b"e.ipcRenderer.sendSync('read')")
        self.assertNotIn('api_outline',result)
        self.assertFalse(result['coverage']['semantic_analysis_complete'])

    def test_destructured_and_lexical_aliases(self):
        result=inspect("const e=require('electron');const {ipcRenderer:io}=e;const alias=io;e.contextBridge.exposeInMainWorld('Sample',{read:()=>alias.invoke('read')});")
        self.assertEqual(result['selected_api']['ipc_calls'][0]['origin'][-1],'invoke')

    def test_esm_namespace_named_aliases_and_imported_require_shadow(self):
        source="import * as e from 'electron';import {ipcRenderer as io} from 'electron';e.contextBridge.exposeInMainWorld('Sample',{read:()=>io.invoke('read')});"
        result=inspect(source)
        self.assertEqual(result['selected_api']['ipc_calls'][0]['origin'],['module','electron','ipcRenderer','invoke'])
        result=inspect(direct("import require from 'fake';const e=require('electron');"))
        self.assertNotIn('selected_api',result)

    def test_webpack_loader_supported_structural_recipe_and_renaming(self):
        for names in [('table','cache','load','61'),('factories','stored','dispatch','8')]:
            source=webpack(*names)
            raw=source.encode();focus=raw.index(b'e.contextBridge.exposeInMainWorld')
            result=inspect_binding(raw,focus,'read')
            self.assertEqual(result.get('namespace'),'Sample',result)
            self.assertEqual(result['selected_api']['ipc_calls'][0]['channel'],'read')
            self.assertTrue(any('webpack_dispatch' in step for step in result['static_steps']))

    def test_webpack_fake_return_or_cache_write_cannot_resolve(self):
        good=webpack()
        for source in [good.replace(',mod.exports;}',',{};}'),
                       good.replace('const e=load(61);','cache[61]={exports:fake};const e=load(61);'),
                       good.replace('const e=load(61);','const other=table;other[61]=fake;const e=load(61);'),
                       good.replace("mod.exports=require('electron')",'mod.exports=fake'),
                       good.replace('if(void 0!==cached)','if(true)')]:
            raw=source.encode();focus=raw.index(b'e.contextBridge.exposeInMainWorld')
            result=inspect_binding(raw,focus,'read')
            self.assertNotIn('selected_api',result,result)
            self.assertTrue(result['unresolved'])

    def test_table_and_cache_aggregate_aliases_are_not_checked_loader_state(self):
        for extra in ('const box={table};box.table[61]=fake;',
                      'const box={cache};box.cache[61]={exports:fake};'):
            source=webpack().replace('const e=load(61);',extra+'const e=load(61);')
            result=inspect(source)
            self.assertIsNone(result.get('callee_origin'),result)
            self.assertFalse(result.get('selected_api',{}).get('ipc_calls'))

    def test_shadowing_and_mutation_never_become_electron_binding(self):
        for source in [direct("const e={contextBridge:fake,ipcRenderer:fake};"),
                       direct("let e=require('electron');"),
                       direct("const e=require('electron');e.ipcRenderer=fake;"),
                       direct("const e=require('electron');const alias=e;alias.ipcRenderer=fake;"),
                       direct("require=fake;const e=require('electron');"),
                       direct("const e=require('electron');delete e.ipcRenderer;"),
                       direct("const e=require('electron');Object.defineProperty(e,'ipcRenderer',{value:fake});"),
                       direct("function require(x){return fake}const e=require('electron');")]:
            result=inspect(source)
            self.assertNotIn('selected_api',result,result)
        raw=b"const e=require('electron');function f(e){e.contextBridge.exposeInMainWorld('x',{read:()=>e.ipcRenderer.send('x')})}"
        result=inspect_binding(raw,raw.index(b'e.contextBridge.exposeInMainWorld'),'read')
        self.assertNotIn('selected_api',result)

    def test_generator_async_and_accessor_factories_are_not_executed_exports(self):
        for modifier in ('*', 'async ', 'get '):
            source=webpack().replace('61(mod){', modifier+'61(mod){', 1)
            result=inspect(source)
            self.assertFalse(result.get('selected_api',{}).get('ipc_calls'),result)
            self.assertTrue(result['unresolved'])

    def test_module_arguments_and_member_receivers_escape_unmodeled_calls(self):
        prefixes=(
            "function mutate(x){x.ipcRenderer={sendSync(){}}}const e=require('electron');mutate(e);",
            "const e=require('electron');const alias=e;unmodeled(alias);",
            "const e=require('electron');unmodeled(e.ipcRenderer);",
            "const e=require('electron');const member=e.ipcRenderer;member.customMethod();",
            "const e=require('electron');const mutate=Object.assign;mutate(e,{ipcRenderer:fake});",
            "const e=require('electron');unmodeled.call(null,e);",
            "const e=require('electron');unmodeled({receiver:e});",
            "const e=require('electron');const container={receiver:e};unmodeled(container);",
            "const e=require('electron');unmodeled(()=>e.ipcRenderer);",
        )
        for prefix in prefixes:
            with self.subTest(prefix=prefix):
                result=inspect(direct(prefix))
                self.assertFalse(result.get('selected_api',{}).get('ipc_calls'),result)
                self.assertIn('module_receiver_mutated_or_escaped',result['unresolved'])
                self.assertIsNotNone(result['lexical_callee_origin'])
                self.assertIsNone(result['callee_origin'])

    def test_callback_with_only_modeled_receiver_call_does_not_pass_receiver(self):
        source=direct("const e=require('electron');signal.addEventListener('abort',()=>{e.ipcRenderer.off('read',callback)});")
        result=inspect(source)
        self.assertEqual(result['selected_api']['ipc_calls'][0]['channel'],'read')
        # Returning the receiver from the callback is still an escape.
        result=inspect(direct("const e=require('electron');unmodeled(()=>e.ipcRenderer);"))
        self.assertFalse(result.get('selected_api',{}).get('ipc_calls'))

    def test_dynamic_channel_and_nested_callback_are_not_direct_edges(self):
        result=inspect(direct(call='e.ipcRenderer.sendSync(channels.value)'))
        self.assertIsNone(result['selected_api']['ipc_calls'][0]['channel'])
        self.assertIn('dynamic_or_unsupported_channel_expression',result['unresolved'])
        result=inspect(direct(call="()=>e.ipcRenderer.sendSync('later')"))
        self.assertEqual(result['selected_api']['ipc_calls'],[])
        self.assertIn('nested_callback_call_not_asserted_as_direct_API_path',result['unresolved'])

    def test_object_spreads_duplicates_eval_and_incomplete_scope(self):
        for source in [direct().replace("read:()=>e.ipcRenderer.sendSync('read')", "read:()=>e.ipcRenderer.sendSync('read'),...other"),
                       direct().replace("read:()=>e.ipcRenderer.sendSync('read')", "read:()=>e.ipcRenderer.sendSync('read'),read:()=>fake()"),
                       direct(tail="eval(code)")]:
            result=inspect(source)
            self.assertTrue(result['unresolved'])
            self.assertFalse(result.get('selected_api',{}).get('ipc_calls'))
        model=Slice(direct().encode(),max_nodes=1)
        self.assertFalse(model.complete)
        with patch('eaos.js_bindings.Slice',return_value=model):
            result=inspect_binding(direct().encode(),0,'read')
        self.assertNotIn('selected_api',result)

    def test_getters_generators_and_parse_errors_are_not_direct_API_paths(self):
        for body in ("get read(){return e.ipcRenderer.sendSync('read')}",
                     "*read(){e.ipcRenderer.sendSync('read')}",
                     "read:function*(){e.ipcRenderer.sendSync('read')}"):
            result=inspect("const e=require('electron');e.contextBridge.exposeInMainWorld('Sample',{"+body+"});")
            self.assertFalse(result.get('selected_api',{}).get('ipc_calls'),result)
            self.assertTrue(result['unresolved'])
        result=inspect(direct(tail='const broken=;'))
        self.assertNotIn('selected_api',result)
        self.assertIn('parse_errors_in_binding_scope',result['unresolved'])

    def test_shorthand_and_computed_methods_cannot_hide_overrides(self):
        for body in ("read:()=>e.ipcRenderer.sendSync('read'),read",
                     "read:()=>e.ipcRenderer.sendSync('read'),[unknown](){return fake}"):
            result=inspect("const e=require('electron');e.contextBridge.exposeInMainWorld('Sample',{"+body+"});")
            self.assertFalse(result.get('selected_api',{}).get('ipc_calls'),result)
            self.assertTrue(result['unresolved'])

    def test_focus_must_be_observed_call_and_no_source_execution(self):
        result=inspect_binding(b"throw new Error('must never execute')",0,'read')
        self.assertTrue(result['unresolved'])
        result=inspect(direct(),api=None)
        self.assertEqual(result['api_outline'][0]['name'],'read')
        self.assertNotIn('selected_api',result)

    def test_owned_operation_keeps_index_and_evidence_identity(self):
        with tempfile.TemporaryDirectory() as tmp:
            base=Path(tmp);root=base/'Fixture.app';root.mkdir();raw=direct().encode()
            (root/'preload.js').write_bytes(raw)
            session=ApplicationSession(root,base/'cache')
            try:
                component=session.call('inventory_application',{})['data']['items'][0]['component_id']
                syntax=session.call('inspect_javascript',{'component_id':component,'find':'exposeInMainWorld'})
                focus=syntax['data']['observations'][0]['start_byte']
                index_before={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (base/'cache/javascript').rglob('*.json')}
                result=session.call('inspect_javascript',{'component_id':component,'binding_at':focus,'api':'read'})
                self.assertEqual(result['data']['selected_api']['ipc_calls'][0]['channel'],'read')
                self.assertEqual(index_before,{str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (base/'cache/javascript').rglob('*.json')})
                evidence=session.call('read_evidence',{'id':result['evidence']['id'],'limit':40000})
                for args in [{'component_id':component,'api':'read'},
                             {'component_id':component,'binding_at':focus,'offset':1},
                             {'component_id':component,'binding_at':focus,'source_offset':0}]:
                    with self.assertRaises(ValueError):session.call('inspect_javascript',args)
            finally:session.close()
            reopened=ApplicationSession(root,base/'cache')
            try:
                reopened.call('inventory_application',{})
                self.assertEqual(reopened.call('read_evidence',{'id':result['evidence']['id'],'limit':40000})['text'],evidence['text'])
            finally:reopened.close()
            self.assertEqual((root/'preload.js').read_bytes(),raw)
