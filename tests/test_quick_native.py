"""Small local fixtures only. Never execute any of the compiled targets."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from eaos.backend import Backend


@unittest.skipUnless(os.environ.get('EAOS_NATIVE_TESTS')=='1','requires existing Java/Ghidra and Apple toolchain')
class QuickNative(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary=tempfile.TemporaryDirectory(prefix='eaos-small-fixtures-')
        cls.root=Path(cls.temporary.name)
        source=Path(__file__).parent
        cls.objc=cls.root/'objc'
        subprocess.run(['clang','-O0','-fobjc-arc','-framework','Foundation',str(source/'quick_fixture.m'),'-o',str(cls.objc)],check=True)
        cls.swift=cls.root/'swift'
        subprocess.run(['swiftc','-Onone',str(source/'quick_fixture.swift'),'-o',str(cls.swift)],check=True)
        cls.arm=cls.root/'arm'
        cls.x86=cls.root/'x86'
        for architecture,destination in [('arm64',cls.arm),('x86_64',cls.x86)]:
            subprocess.run(['clang','-arch',architecture,'-mmacosx-version-min=13.0','-O0',str(source/'fixture.c'),'-o',str(destination)],check=True)
        cls.universal=cls.root/'universal'
        subprocess.run(['lipo','-create',str(cls.x86),str(cls.arm),'-output',str(cls.universal)],check=True)

    @classmethod
    def tearDownClass(cls):cls.temporary.cleanup()

    def backend(self,target,**args):
        backend=Backend(str(target),**args);self.addCleanup(backend.close);return backend

    def test_architecture_bytes_languages_unavailable_and_wrong_cache(self):
        arm=self.backend(self.universal,architecture='arm64')
        result=arm.open_program()
        self.assertEqual(str(arm.program.getLanguageID()),'AARCH64:LE:64:AppleSilicon')
        self.assertEqual(arm.import_snapshot.read_bytes(),self.arm.read_bytes())
        arm.close()
        x86=self.backend(self.universal,architecture='x86_64')
        x86.open_program()
        self.assertTrue(str(x86.program.getLanguageID()).startswith('x86:'))
        self.assertNotEqual(arm.directory,x86.directory);x86.close()
        # Poison the selected profile with a real project for the other slice.
        shutil.rmtree(arm.directory/'ghidra')
        shutil.copytree(x86.directory/'ghidra',arm.directory/'ghidra')
        bad=self.backend(self.universal,architecture='arm64')
        with self.assertRaisesRegex(RuntimeError,'hash does not match|Wrong-architecture'):
            bad.open_program()
        self.assertIsNone(bad.program)
        with self.assertRaisesRegex(ValueError,'unavailable'):
            Backend(str(self.arm),architecture='x86_64')

    def test_quick_reads_names_independent_functions_failure_and_reopen(self):
        backend=self.backend(self.objc,analysis_mode='quick')
        with patch('pyghidra.analyze',side_effect=AssertionError('quick ran full analysis')):
            opened=backend.open_program()
        self.assertEqual(opened['analysis']['scope'],'partial')
        found=backend.search(kind='functions',pattern='FixtureAlpha')
        index_coverage=found['data']['coverage']['function_candidates']
        self.assertEqual(index_coverage['candidates_available'],len(backend.quick_metadata['function_starts']))
        self.assertFalse(index_coverage['truncated'])
        qualified=found['data']['items']
        self.assertTrue(any('FixtureAlpha::' in r.get('qualified_name','')for r in qualified))
        duplicates=backend.search(kind='functions',pattern='value:')['data']['items']
        self.assertGreaterEqual(len({r['address']for r in duplicates}),2)
        literal=backend.search(kind='strings',pattern='EAOS quick fixture unique literal')['data']['items']
        self.assertTrue(literal);self.assertFalse(literal[0]['references_complete'])
        self.assertEqual(backend.read_memory(literal[0]['address'],length=4)['data']['hex'],'45414f53')
        first=backend.search(kind='functions',pattern='fixture_first')['data']['items'][0]['address']
        second=backend.search(kind='functions',pattern='fixture_second')['data']['items'][0]['address']
        self.assertFalse(backend.function_readiness)
        result=backend.inspect([first])
        self.assertIn('pseudocode',result['data'][0],result)
        self.assertEqual(set(backend.function_readiness),{first})
        previous_id=result['evidence']['id'];revision=backend.revision
        artifact=next((backend.evidence.directory).glob('artifact-*.c'))
        old_code=artifact.read_bytes()
        backend.inspect([second],mode='assembly')
        self.assertGreater(backend.revision,revision)
        self.assertEqual(set(backend.function_readiness),{first,second})
        self.assertFalse(backend.inspection_cache)
        from ghidra.program.model.symbol import SourceType
        transaction=backend.program.startTransaction('Fixture overloaded qualified names')
        try:
            namespace=backend.program.getSymbolTable().createNameSpace(None,'FixtureOverloads',SourceType.USER_DEFINED)
            for address in (first,second):
                function=backend.program.getFunctionManager().getFunctionAt(backend.address(address))
                function.setParentNamespace(namespace)
                function.setName('overloaded',SourceType.USER_DEFINED)
            overloads=backend.search(kind='functions',pattern='FixtureOverloads::overloaded')['data']['items']
            self.assertEqual({item['address']for item in overloads},{first,second})
        finally:backend.program.endTransaction(transaction,False)
        transaction=backend.program.startTransaction('Fixture alias')
        try:
            backend.program.getSymbolTable().createLabel(backend.address(first),'fixture_alias',SourceType.USER_DEFINED)
            alias=backend.search(kind='functions',pattern='fixture_alias')['data']['items']
            self.assertEqual(alias[0]['address'],first)
        finally:backend.program.endTransaction(transaction,False)
        # This tiny fixture imports class data, not objc_release. Supply a real
        # Ghidra external function record and verify address-space-safe lookup.
        transaction=backend.program.startTransaction('Fixture external function')
        try:
            location=backend.program.getExternalManager().addExtFunction(
                'fixture_library','fixture_external',None,SourceType.USER_DEFINED)
            external=backend.search(kind='functions',pattern='fixture_external')['data']['items']
            self.assertEqual(len(external),1)
            self.assertTrue(external[0]['external'])
            self.assertTrue(external[0]['address'].startswith('EXTERNAL:'))
            result=backend.inspect([external[0]['address']])['data'][0]
            self.assertIn('External function',result['decompile_error'])
            self.assertEqual(result['instructions'],[])
        finally:backend.program.endTransaction(transaction,False)
        with patch('eaos.native_inspection.build',side_effect=RuntimeError('controlled decompiler failure')):
            fallback=backend.inspect([first])['data'][0]
        self.assertEqual(fallback['decompile_error'],'controlled decompiler failure')
        self.assertTrue(fallback['instructions'])
        self.assertEqual(artifact.read_bytes(),old_code)
        self.assertIn(previous_id,backend.read_evidence(previous_id)['text'])
        backend.close()
        reopened=self.backend(self.objc,analysis_mode='quick')
        reopened.open_program()
        self.assertEqual(reopened.revision,revision+1)
        self.assertEqual(set(reopened.function_readiness),{first,second})
        self.assertIn(previous_id,reopened.read_evidence(previous_id)['text'])
        from ghidra.program.util import GhidraProgramUtilities
        self.assertFalse(GhidraProgramUtilities.isAnalyzed(reopened.program))
        reopened.open_program(analysis_mode='full')
        self.assertTrue(GhidraProgramUtilities.isAnalyzed(reopened.program))
        self.assertEqual(reopened.analysis_mode,'full')
        self.assertIn(previous_id,reopened.read_evidence(previous_id)['text'])

    def test_swift_objc_metadata_and_stale_quick_cache(self):
        backend=self.backend(self.swift,analysis_mode='quick')
        backend.open_program()
        rows=backend.search(kind='functions',pattern='EAOSSwiftFixture')['data']['items']
        self.assertTrue(rows)
        backend.close()
        state=backend.directory/'quick.json';data=json.loads(state.read_text());data['revision']+=1;state.write_text(json.dumps(data))
        stale=self.backend(self.swift,analysis_mode='quick')
        with self.assertRaisesRegex(RuntimeError,'Stale/corrupt'):
            stale.open_program()
        self.assertTrue(state.exists())

    def test_mapped_byte_validation_rejects_modified_project_with_same_input_hash(self):
        directory=self.root/'corrupt-bytes';directory.mkdir()
        target=directory/'fixture';shutil.copyfile(self.arm,target)
        backend=self.backend(target)
        backend.open_program()
        text=next(s for s in backend.quick_metadata['sections']if s['name']=='__text')
        at=backend.program.getAddressFactory().getDefaultAddressSpace().getAddress(text['address'])
        transaction=backend.program.startTransaction('Fixture cache corruption')
        try:
            backend.program.getListing().clearCodeUnits(at,at.add(3),False)
            image=backend.program.getMemory();image.setByte(at,int(image.getByte(at))^1)
        finally:backend.program.endTransaction(transaction,True)
        backend.program.save('Fixture modified cache',backend.monitor);backend.close()
        reopened=self.backend(target)
        with self.assertRaisesRegex(RuntimeError,'executable bytes'):
            reopened.open_program()
        self.assertTrue((reopened.directory/'ghidra').exists())

    def test_loaded_compiler_provenance_missing_or_corrupt_is_rejected(self):
        target=self.root/'compiler-fixture';shutil.copyfile(self.arm,target)
        backend=self.backend(target);backend.open_program();backend.close()
        path=backend.directory/'loaded.json';original=path.read_text()
        for replacement in (None,'{broken',original.replace('"compiler": "default"','"compiler": "other"')):
            if replacement==original:
                data=json.loads(original);data['compiler']='wrong';replacement=json.dumps(data)
            if replacement is None:path.unlink()
            else:path.write_text(replacement)
            bad=self.backend(target)
            with self.assertRaisesRegex(RuntimeError,'provenance missing or corrupt'):bad.open_program()
            self.assertTrue((backend.directory/'ghidra').exists())
            path.write_text(original)

    def test_owned_session_quick_to_full_preserves_evidence(self):
        from eaos.session import McpSession
        target=self.root/'session-fixture';shutil.copyfile(self.arm,target)
        backend=Backend(str(target),analysis_mode='quick')
        session=McpSession(backend,initial_wait=0.05,analysis_timeout=30)
        self.addCleanup(session.close)
        session.wait_ready()
        first=session.call('open_program',{})
        self.assertEqual(first['analysis']['scope'],'partial')
        found=session.call('search',{'kind':'functions','pattern':'quote'})
        self.assertTrue(found['data']['items'])
        session.wait_ready('full')
        last=session.call('open_program',{})
        self.assertEqual(last['analysis']['scope'],'whole_program_pass')
        self.assertIn(first['evidence']['id'],session.call('read_evidence',{'id':first['evidence']['id']})['text'])

    def test_bounded_discovery_continuation_reopens_and_preserves_evidence(self):
        directory=self.root/'continued-discovery';directory.mkdir()
        target=directory/'fixture';shutil.copyfile(self.objc,target)
        backend=self.backend(target,analysis_mode='quick');backend.open_program()
        with patch('eaos.quick.MAX_NAME_CANDIDATES',2):
            first=backend.search(kind='functions',pattern='fixture_second')
            self.assertEqual(first['data']['matches'],0,'Late candidate was unexpectedly in the first batch')
            evidence=first['evidence']['id'];earlier=backend.read_evidence(evidence)['text']
            old_view=first['data']['view'];old_cursor=first['data']['coverage']['function_candidates']['next_index_cursor']
            result=first
            while result['data']['coverage']['function_candidates']['can_continue']:
                cursor=result['data']['coverage']['function_candidates']['next_index_cursor']
                result=backend.search(kind='functions',pattern='fixture_second',index_cursor=cursor)
            self.assertEqual(result['data']['matches'],1)
            count=result['data']['coverage']['function_candidates']['candidates_available']
            positions=backend.discovery_index.db.execute('SELECT position FROM candidates ORDER BY position').fetchall()
            self.assertEqual([r[0]for r in positions],list(range(count)))
        backend.close()
        reopened=self.backend(target,analysis_mode='quick');reopened.open_program()
        result=reopened.search(kind='functions',pattern='fixture_second')
        self.assertTrue(result['data']['coverage']['function_candidates']['index_complete'])
        self.assertEqual(result['data']['matches'],1)
        self.assertEqual(reopened.read_evidence(evidence)['text'],earlier)
        with self.assertRaisesRegex(ValueError,'expanded or reset'):
            reopened.search(kind='functions',pattern='fixture_second',offset=1,view=old_view)
        with self.assertRaisesRegex(ValueError,'expanded or reset'):
            reopened.search(kind='functions',index_cursor=old_cursor)

    def test_discovery_cursor_rejects_actual_other_architecture_and_full_profile(self):
        directory=self.root/'cursor-architecture';directory.mkdir()
        target=directory/'universal';shutil.copyfile(self.universal,target)
        arm=self.backend(target,analysis_mode='quick',architecture='arm64');arm.open_program()
        with patch('eaos.quick.MAX_NAME_CANDIDATES',1):
            found=arm.search(kind='functions')
        cursor=found['data']['coverage']['function_candidates']['next_index_cursor']
        self.assertIsNotNone(cursor);arm.close()
        x86=self.backend(target,analysis_mode='quick',architecture='x86_64');x86.open_program()
        with self.assertRaisesRegex(ValueError,'another input, architecture, profile'):
            x86.search(kind='functions',index_cursor=cursor)
        self.assertFalse((x86.directory/'function-index-v1.sqlite').exists())
        x86.close()
        full=self.backend(target,architecture='arm64');full.open_program()
        with self.assertRaisesRegex(ValueError,'quick profile'):
            full.search(kind='functions',index_cursor=cursor)
        self.assertIn(found['evidence']['id'],full.read_evidence(found['evidence']['id'])['text'])

    def test_preparation_invalidates_revision_but_cached_inspection_reuses_progress(self):
        directory=self.root/'preparation-index-lifecycle';directory.mkdir()
        target=directory/'fixture';shutil.copyfile(self.objc,target)
        backend=self.backend(target,analysis_mode='quick');backend.open_program()
        found=backend.search(kind='functions',pattern='fixture_first')
        address=found['data']['items'][0]['address'];old_view=found['data']['view']
        evidence=found['evidence']['id'];earlier=backend.read_evidence(evidence)['text']
        revision=backend.revision
        backend.inspect([address],mode='assembly')
        self.assertGreater(backend.revision,revision)
        self.assertIsNone(backend.discovery_index)
        with self.assertRaisesRegex(ValueError,'revision changed'):
            backend.search(kind='functions',pattern='fixture_first',view=old_view)
        with patch('eaos.quick.MAX_NAME_CANDIDATES',2):
            initial=backend.search(kind='functions')
            self.assertEqual(initial['data']['coverage']['function_candidates']['candidates_indexed'],2)
            expanded=backend.search(kind='functions',index_cursor=initial['data']['coverage']['function_candidates']['next_index_cursor'])
        self.assertEqual(expanded['data']['coverage']['function_candidates']['candidates_indexed'],4)
        index=backend.discovery_index;revision=backend.revision
        backend.inspect([address],mode='assembly')
        self.assertEqual(backend.revision,revision)
        self.assertIs(backend.discovery_index,index)
        reused=backend.search(kind='functions',view=expanded['data']['view'],offset=1)
        self.assertEqual(reused['data']['coverage']['function_candidates']['candidates_indexed'],4)
        backend.close()
        reopened=self.backend(target,analysis_mode='quick');reopened.open_program()
        self.assertEqual(reopened.search(kind='functions')['data']['coverage']['function_candidates']['candidates_indexed'],4)
        self.assertEqual(reopened.read_evidence(evidence)['text'],earlier)


if __name__=='__main__':unittest.main()
