import unittest
from eaos.js_bindings import inspect_binding
from eaos.js_literals import resolve_string
from test_js_bindings import direct, inspect, webpack


def enum_bundle(body='X.A="different-from-key"', after='', before='', export_prefix=''):
    factory='77(mod,out){var local;'+before+export_prefix+'(function(X){'+body+'})(local||(out.Events=local={}));'+after+'}'
    source=webpack().replace("{61(mod){",'{'+factory+',61(mod){',1)
    source=source.replace('const e=load(61);','const e=load(61);const channels=load(77);')
    return source.replace("sendSync('read')",'sendSync(channels.Events.A)')


class LiteralDeclarations(unittest.TestCase):
    def test_const_and_closed_objects_use_values_not_property_spelling(self):
        for declaration,expr in [("const channel='wire-value';",'channel'),
                                 ("const channels={A:'wire-value'};",'channels.A'),
                                 ("const channels={nested:{A:'wire-value'}};",'channels.nested.A')]:
            result=inspect(direct("const e=require('electron');"+declaration,call='e.ipcRenderer.sendSync('+expr+')'))
            call=result['selected_api']['ipc_calls'][0]
            self.assertEqual(call['channel'],'wire-value')
            self.assertIn('definition',call['channel_provenance'])
            self.assertNotEqual(call['channel_provenance']['definition'],call['channel_provenance']['use'])

    def test_enum_export_is_a_closed_literal_recipe_with_provenance(self):
        result=inspect(enum_bundle())
        call=result['selected_api']['ipc_calls'][0]
        self.assertEqual(call['channel'],'different-from-key')
        self.assertEqual(call['channel_status'],'computed_closed_enum_literal')
        self.assertIn('factory',call['channel_provenance'])
        self.assertIn('export_assignment',call['channel_provenance'])
        self.assertIn('module_dispatch',call['channel_provenance'])

    def test_duplicate_dynamic_overwrite_side_effect_and_prototype_fields_refuse(self):
        cases=[enum_bundle('X.A="one",X.A="two"'),
               enum_bundle('X[key]="value"'),enum_bundle('X.A=getValue()'),
               enum_bundle('X.A="one";unknown()'),
               enum_bundle('X.__proto__="unsafe",X.A="one"'),
               enum_bundle('X.constructor="unsafe",X.A="one"'),
               enum_bundle(after='out.Events.A="changed";'),
               enum_bundle(after='out.Events={A:"changed"};'),
               enum_bundle(after='local.A="changed";'),
               enum_bundle(after='mutate(local);'),
               enum_bundle(after='Object.defineProperty(out,"Events",{value:fake});'),
               enum_bundle(after='const alias=out;alias.Events={A:"changed"};'),
               enum_bundle(before='Object.defineProperty(Object.prototype,"A",{set:handler});')]
        for source in cases:
            with self.subTest(source=source):
                result=inspect(source)
                self.assertIsNone(result['selected_api']['ipc_calls'][0]['channel'],result)

    def test_unset_local_and_unique_export_are_required(self):
        for source in [enum_bundle().replace('var local;','var local=existing;'),
                       enum_bundle().replace('(local||(out.Events=local={}))','(other||(out.Events=local={}))'),
                       enum_bundle().replace('function(X){','function*(X){'),
                       enum_bundle().replace('function(X){','async function(X){')]:
            result=inspect(source)
            self.assertIsNone(result['selected_api']['ipc_calls'][0]['channel'],result)

    def test_object_alias_escapes_and_overwritten_keys_refuse(self):
        for declaration in ["const channels={A:'one',A:'two'};",
                            "const channels={__proto__:'unsafe',A:'one'};",
                            "const channels={A:'one'};const alias=channels;alias.A='two';",
                            "const channels={A:'one'};mutate(channels);",
                            "const channels={A:'one'};globalThis.shared=channels;",
                            "const channels={A:'one',other:unknown()};",
                            "const channels={A:'one',other:external};"]:
            result=inspect(direct("const e=require('electron');"+declaration,call='e.ipcRenderer.sendSync(channels.A)'))
            self.assertIsNone(result['selected_api']['ipc_calls'][0]['channel'],result)

    def test_review_aggregate_aliases_and_escapes_fail_closed(self):
        for extra in ("const box={channels};box.channels.A='two';",
                      "mutate({channels});", "mutate([channels]);",
                      "const box={nested:{channels}};box.nested.channels.A='two';",
                      "const callback=()=>channels;unmodeled(callback);"):
            result=inspect(direct("const e=require('electron');const channels={A:'one'};"+extra,call='e.ipcRenderer.sendSync(channels.A)'))
            self.assertIsNone(result['selected_api']['ipc_calls'][0]['channel'],result)
        for extra in ('out.other=local;', 'out.getEnum=()=>local;', 'mutate({local});'):
            result=inspect(enum_bundle(after=extra))
            self.assertIsNone(result['selected_api']['ipc_calls'][0]['channel'],result)

    def test_conditional_nested_or_unreachable_initializers_are_not_values(self):
        for prefix in ('if(false)', 'if(condition)', 'return;', 'throw failure;', 'while(condition)', 'false&&'):
            source=enum_bundle().replace('(function(X){',prefix+'(function(X){',1)
            result=inspect(source)
            self.assertFalse(result['coverage']['tree_has_parse_errors'])
            self.assertIsNone(result['selected_api']['ipc_calls'][0]['channel'],result)
        source=enum_bundle().replace('(function(X){','{(function(X){',1).replace('local={}));','local={}));}',1)
        result=inspect(source)
        self.assertFalse(result['coverage']['tree_has_parse_errors'])
        self.assertIsNone(result['selected_api']['ipc_calls'][0]['channel'])

    def test_mutation_capable_receiver_and_second_cached_import_are_unknown(self):
        for source in [enum_bundle(after='out.__defineGetter__("Events",()=>({A:"changed"}));'),
                       enum_bundle(after='out.Events.__defineGetter__("A",()=>"changed");'),
                       enum_bundle().replace('const channels=load(77);','const channels=load(77);const another=load(77);another.Events.A="changed";'),
                       enum_bundle().replace('const channels=load(77);','const channels=load(77);mutate(load(77));'),
                       enum_bundle(after='const importer=load;const another=importer(77);another.Events.A="changed";'),
                       enum_bundle(after='const box={load};mutate(box);'),
                       enum_bundle(after='const importer=load.bind(null);const another=importer(77);another.Events.A="changed";')]:
            result=inspect(source)
            self.assertFalse(result['coverage']['tree_has_parse_errors'])
            self.assertIsNone(result['selected_api']['ipc_calls'][0]['channel'],result)
        source=enum_bundle().replace('const channels=load(77);','const channels=load(77);const another=load(77);const scalar=another.Events.A;')
        result=inspect(source)
        self.assertEqual(result['selected_api']['ipc_calls'][0]['channel'],'different-from-key')

    def test_equal_ids_and_variable_names_in_separate_cache_are_not_aliases(self):
        other=enum_bundle().replace("e.contextBridge.exposeInMainWorld('Sample',{read:()=>e.ipcRenderer.sendSync(channels.Events.A)});",'channels.Events.A="separate-cache-value";')
        source=enum_bundle().replace('const channels=load(77);','const channels=load(77);'+other)
        # Isolate literal/cache identity from the separately conservative
        # whole-source Electron receiver escape check.
        from eaos.js_bindings import Slice, children
        model=Slice(source.encode())
        target=source.encode().rfind(b'e.ipcRenderer.sendSync')
        call=next(n for n in model.nodes if n.type=='call_expression' and n.start_byte==target)
        argument=children(call.child_by_field_name('arguments'))[0]
        self.assertEqual(resolve_string(model,argument)['value'],'different-from-key')

    def test_implicit_third_loader_parameter_is_not_unmodeled_cache_alias(self):
        for factory in ('88(mod,out,req){const another=req(77);another.Events.A="changed";}',
                        '88:(mod,out,req)=>{const another=req(77);another.Events.A="changed";}'):
            source=enum_bundle().replace(',61(mod){',','+factory+',61(mod){').replace('const channels=load(77);','const channels=load(77);load(88);')
            result=inspect(source)
            self.assertFalse(result['coverage']['tree_has_parse_errors'])
            self.assertFalse(result.get('selected_api',{}).get('ipc_calls'))
            self.assertTrue(result['unresolved'])

    def test_module_exports_and_implicit_factory_aliases_are_not_ignored(self):
        sources=[enum_bundle(after='mod.exports.Events.A="changed";')]
        for factory in ('88(){this[77]=fake;}',
                        '88(){const another=arguments[2](77);another.Events.A="changed";}'):
            sources.append(enum_bundle().replace(',61(mod){',','+factory+',61(mod){').replace('const channels=load(77);','load(88);const channels=load(77);'))
        for source in sources:
            result=inspect(source)
            self.assertFalse(result['coverage']['tree_has_parse_errors'])
            self.assertFalse(result.get('selected_api',{}).get('ipc_calls') and result['selected_api']['ipc_calls'][0]['channel'],result)

    def test_different_module_ids_or_factory_names_are_not_hardcoded(self):
        source=enum_bundle().replace('77(','42(').replace('load(77)','load(42)').replace('out.Events','out.Messages').replace('channels.Events.A','channels.Messages.A')
        result=inspect(source)
        self.assertEqual(result['selected_api']['ipc_calls'][0]['channel'],'different-from-key')
