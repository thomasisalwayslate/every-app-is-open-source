import tempfile
import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch
from types import SimpleNamespace

from eaos.quick import walk
from eaos import quick
from eaos import function_discovery
from eaos.evidence import Evidence
from eaos.backend import Backend


class CandidateCoverage(unittest.TestCase):
    def setUp(self):
        temporary=tempfile.TemporaryDirectory();self.addCleanup(temporary.cleanup)
        target=Path(temporary.name)/'fixture';target.write_bytes(b'fake metadata input, never executed')
        self.backend=Backend(str(target),analysis_mode='quick');self.addCleanup(self.backend.close)
        self.backend._load=Mock()
        self.backend.program=program=Mock()
        # Prevent fake Java objects from reaching Backend.close.
        self.addCleanup(lambda:setattr(self.backend,'program',None))
        program.getLanguageID.return_value='AARCH64:LE:64:AppleSilicon'
        program.getCompilerSpec.return_value.getCompilerSpecID.return_value='default'
        program.getFunctionManager.return_value.getFunctions.return_value=[]
        program.getFunctionManager.return_value.getExternalFunctions.return_value=[]
        program.getFunctionManager.return_value.getFunctionAt.return_value=None
        program.getAddressFactory.return_value.getDefaultAddressSpace.return_value.getAddress.side_effect=lambda at:f'{at:08x}'
        program.getSymbolTable.return_value.getPrimarySymbol.return_value=None
        program.getSymbolTable.return_value.getSymbols.return_value=[]
        self.backend.quick_metadata={'function_starts':[0x100,0x104,0x108]}

    def check_coverage(self,result,indexed,truncated,reason,available=3):
        coverage=result['data']['coverage']['function_candidates']
        self.assertEqual(coverage['candidates_indexed'],indexed)
        self.assertEqual(coverage['candidates_available'],available)
        self.assertEqual(coverage['truncated'],truncated)
        self.assertEqual(coverage['reason'],reason)
        saved=json.loads(self.backend.read_evidence(result['evidence']['id'])['text'])
        self.assertEqual(saved['data']['coverage']['function_candidates'],coverage)

    def test_count_cutoff_cached_omissions_and_invalidation_are_visible(self):
        with patch('eaos.quick.MAX_NAME_CANDIDATES',2):
            first=self.backend.search(kind='functions',limit=1)
        self.check_coverage(first,2,True,'candidate_limit')
        self.assertEqual(first['data']['next_offset'],1)
        page=self.backend.search(kind='functions',offset=1,view=first['data']['view'])
        self.check_coverage(page,2,True,'candidate_limit')
        missing=self.backend.search(kind='functions',pattern='00000108')
        self.assertEqual(missing['data']['matches'],0)
        self.check_coverage(missing,2,True,'candidate_limit')
        self.backend.invalidate_views()
        self.assertIsNone(self.backend.quick_name_coverage)
        # Reopening a view does not silently expand the persisted prefix.
        self.assertEqual(self.backend.search(kind='functions',pattern='00000108')['data']['matches'],0)
        complete=self.backend.search(kind='functions',pattern='00000108',full=True,
            index_cursor=missing['data']['coverage']['function_candidates']['next_index_cursor'])
        self.assertEqual(complete['data']['matches'],1)
        self.check_coverage(complete,3,False,'complete')

    def test_time_cutoff_reports_zero_indexed_and_available_candidates(self):
        with patch('eaos.function_discovery.monotonic',side_effect=[0,3]+[3]*20):
            result=self.backend.search(kind='functions')
        self.check_coverage(result,0,True,'time_limit')

    def test_time_cutoff_after_partial_indexing_and_empty_index(self):
        self.backend.quick_metadata['function_starts']=list(range(0x100,0x100+300))
        with patch('eaos.function_discovery.monotonic',side_effect=[0]+[0]*256+[3]*30):
            result=self.backend.search(kind='functions')
        self.check_coverage(result,256,True,'time_limit',available=300)

    def test_empty_index_is_complete_without_symbol_recovery_claim(self):
        self.backend.quick_metadata['function_starts']=[]
        self.check_coverage(self.backend.search(kind='functions'),0,False,'complete',available=0)

    def test_multiple_continuations_find_late_match_without_gaps_or_duplicates(self):
        self.backend.quick_metadata['function_starts']=list(range(0x100,0x10a))
        with patch('eaos.quick.MAX_NAME_CANDIDATES',3):
            result=self.backend.search(kind='functions',pattern='00000109')
            self.assertEqual(result['data']['matches'],0)
            positions=[3]
            while result['data']['coverage']['function_candidates']['can_continue']:
                cursor=result['data']['coverage']['function_candidates']['next_index_cursor']
                result=self.backend.search(kind='functions',pattern='00000109',index_cursor=cursor)
                positions.append(result['data']['coverage']['function_candidates']['candidates_indexed'])
            self.assertEqual(positions,[3,6,9,10])
        self.assertEqual(result['data']['matches'],1)
        self.assertTrue(result['data']['coverage']['function_candidates']['index_complete'])
        self.assertIsNone(result['data']['coverage']['function_candidates']['next_index_cursor'])
        stored=self.backend.discovery_index.db.execute('SELECT position,address_key FROM candidates ORDER BY position').fetchall()
        self.assertEqual([r[0]for r in stored],list(range(10)))
        self.assertEqual(len({r[1]for r in stored}),10)

    def test_match_beyond_original_fifty_thousand_cap(self):
        manager=SimpleNamespace(getFunctions=lambda _:[],getExternalFunctions=lambda:[],getFunctionAt=lambda _:None)
        symbols=SimpleNamespace(getPrimarySymbol=lambda _:None,getSymbols=lambda _:[])
        space=SimpleNamespace(getAddress=lambda n:f'{n:08x}')
        self.backend.program=SimpleNamespace(getFunctionManager=lambda:manager,getSymbolTable=lambda:symbols,
            getAddressFactory=lambda:SimpleNamespace(getDefaultAddressSpace=lambda:space),
            getLanguageID=lambda:'fixture',getCompilerSpec=lambda:SimpleNamespace(getCompilerSpecID=lambda:'fixture'))
        self.backend.quick_metadata['function_starts']=list(range(0x100,0x100+50001))
        pattern=f'{0x100+50000:08x}'
        result=self.backend.search(kind='functions',pattern=pattern)
        self.assertEqual(result['data']['matches'],0)
        self.assertLessEqual(result['data']['coverage']['function_candidates']['candidates_indexed'],50000)
        for _ in range(20):
            cursor=result['data']['coverage']['function_candidates']['next_index_cursor']
            if cursor is None:break
            result=self.backend.search(kind='functions',pattern=pattern,index_cursor=cursor)
        self.assertTrue(result['data']['coverage']['function_candidates']['index_complete'])
        self.assertEqual(result['data']['matches'],1)
        self.assertEqual(result['data']['items'][0]['address'],pattern)

    def test_result_pagination_is_pinned_and_expansion_rejects_old_views(self):
        with patch('eaos.quick.MAX_NAME_CANDIDATES',2):
            first=self.backend.search(kind='functions',limit=1)
        view=first['data']['view'];cursor=first['data']['coverage']['function_candidates']['next_index_cursor']
        with self.assertRaisesRegex(ValueError,'requires the returned view'):
            self.backend.search(kind='functions',offset=1)
        second=self.backend.search(kind='functions',offset=1,view=view,limit=1)
        self.assertNotEqual(first['data']['items'][0]['address'],second['data']['items'][0]['address'])
        self.assertEqual(second['data']['coverage']['function_candidates']['candidates_indexed'],2)
        self.assertFalse(second['data']['has_more_results'])
        expanded=self.backend.search(kind='functions',index_cursor=cursor)
        self.assertEqual(len({r['address']for r in expanded['data']['items']}),3)
        for args in ({'offset':1,'view':view},{'index_cursor':cursor}):
            with self.subTest(args=args),self.assertRaisesRegex(ValueError,'expanded or reset'):
                self.backend.search(kind='functions',**args)
        with self.assertRaisesRegex(ValueError,'another query'):
            self.backend.search(kind='functions',pattern='changed',view=expanded['data']['view'])

    def test_no_progress_and_byte_limits_explain_retry_position(self):
        with patch('eaos.quick.NAME_INDEX_SECONDS',0):
            zero=self.backend.search(kind='functions')
        coverage=zero['data']['coverage']['function_candidates']
        self.assertEqual(coverage['candidates_indexed'],0)
        self.assertEqual(coverage['reason'],'time_limit')
        cursor=coverage['next_index_cursor']
        with patch('eaos.function_discovery.BATCH_BYTES',1):
            unchanged=self.backend.search(kind='functions',index_cursor=cursor)
        self.assertEqual(unchanged['data']['coverage']['function_candidates']['reason'],'byte_limit')
        self.assertEqual(unchanged['data']['coverage']['function_candidates']['next_index_cursor'],cursor)
        result=self.backend.search(kind='functions',index_cursor=cursor)
        self.assertEqual(result['data']['coverage']['function_candidates']['candidates_indexed'],3)

    def test_storage_limit_reports_incomplete_and_no_continuation(self):
        with patch('eaos.function_discovery.TOTAL_BYTES',1):
            result=self.backend.search(kind='functions')
        coverage=result['data']['coverage']['function_candidates']
        self.assertEqual(coverage['reason'],'storage_limit')
        self.assertFalse(coverage['index_complete']);self.assertFalse(coverage['can_continue'])
        self.assertIsNone(coverage['next_index_cursor'])
        self.assertEqual(coverage['candidates_indexed'],0)

    def test_query_failure_after_commit_recovers_with_ordinary_search(self):
        with patch('eaos.quick.MAX_NAME_CANDIDATES',1):
            first=self.backend.search(kind='functions')
        cursor=first['data']['coverage']['function_candidates']['next_index_cursor']
        with patch('eaos.function_discovery.QUERY_SECONDS',0),self.assertRaisesRegex(RuntimeError,'committed index preserved'):
            self.backend.search(kind='functions',index_cursor=cursor)
        recovered=self.backend.search(kind='functions')
        self.assertEqual(recovered['data']['coverage']['function_candidates']['candidates_indexed'],3)
        with self.assertRaisesRegex(ValueError,'expanded or reset'):
            self.backend.search(kind='functions',index_cursor=cursor)

    def test_failed_batch_rolls_back_and_reopens_committed_progress(self):
        with patch('eaos.quick.MAX_NAME_CANDIDATES',1):
            first=self.backend.search(kind='functions')
        cursor=first['data']['coverage']['function_candidates']['next_index_cursor']
        identifier=first['evidence']['id'];before=self.backend.read_evidence(identifier)['text']
        index=self.backend.discovery_index;original=index.candidate
        def fail(position,deadline):
            if position==2:raise RuntimeError('controlled batch failure')
            return original(position,deadline)
        with patch.object(index,'candidate',side_effect=fail),self.assertRaisesRegex(RuntimeError,'controlled'):
            self.backend.search(kind='functions',index_cursor=cursor)
        self.assertFalse(index.db.in_transaction)
        self.assertEqual(index.db.execute('SELECT count(*) FROM candidates').fetchone()[0],1)
        self.backend.invalidate_views()
        reopened=self.backend.search(kind='functions')
        self.assertEqual(reopened['data']['coverage']['function_candidates']['candidates_indexed'],1)
        result=self.backend.search(kind='functions',index_cursor=cursor)
        self.assertEqual(result['data']['coverage']['function_candidates']['candidates_indexed'],3)
        self.assertEqual(self.backend.read_evidence(identifier)['text'],before)

    def test_stale_and_foreign_cursor_rejections_do_not_mutate_cache(self):
        with patch('eaos.quick.MAX_NAME_CANDIDATES',1):
            first=self.backend.search(kind='functions')
        cursor=first['data']['coverage']['function_candidates']['next_index_cursor']
        database=self.backend.discovery_index.path;before=database.read_bytes()
        for malformed in ('../../arbitrary','fv1:broken',cursor+'; exec','fi2'+cursor[3:]):
            with self.subTest(cursor=malformed),self.assertRaisesRegex(ValueError,'Malformed'):
                self.backend.search(kind='functions',index_cursor=malformed)
        for change in ({'target_sha256':'wrong'}, {'selection':{'architecture':'x86_64'}}, {'analysis_profile':'full'}):
            with patch.object(self.backend,'identity',{**self.backend.identity,**change}),self.assertRaisesRegex(ValueError,'another input, architecture, profile'):
                self.backend.search(kind='functions',index_cursor=cursor)
        with patch('eaos.function_discovery.SCHEMA_VERSION',2),self.assertRaisesRegex(ValueError,'schema'):
            self.backend.search(kind='functions',index_cursor=cursor)
        self.backend.revision+=1;self.backend.invalidate_views()
        with self.assertRaisesRegex(ValueError,'revision changed'):
            self.backend.search(kind='functions',index_cursor=cursor)
        self.assertEqual(database.read_bytes(),before)
        # An ordinary query explicitly recovers against the new program revision.
        recovered=self.backend.search(kind='functions')
        self.assertEqual(recovered['data']['coverage']['function_candidates']['candidates_indexed'],3)

    def test_changed_native_names_invalidate_result_view(self):
        result=self.backend.search(kind='functions')
        view=result['data']['view']
        self.backend.go_functions={'999':{'address':'00000999','name':'metadata_function'}}
        with self.assertRaisesRegex(ValueError,'changed metadata'):
            self.backend.search(kind='functions',view=view)

    def test_candidate_aliases_duplicates_and_external_space_are_distinct(self):
        def symbol(name,qualified=None):
            item=Mock();item.getName.side_effect=lambda full=False:(qualified or name)if full else name
            return item
        labels={'00000100':symbol('duplicate','One::duplicate'),
                '00000104':symbol('duplicate','Two::duplicate')}
        symbols=self.backend.program.getSymbolTable.return_value
        symbols.getPrimarySymbol.side_effect=lambda at:labels.get(str(at))
        symbols.getSymbols.side_effect=lambda at:[symbol('hidden_alias')]if str(at)=='00000104'else[]
        duplicates=self.backend.search(kind='functions',pattern='duplicate')
        self.assertEqual(duplicates['data']['matches'],2)
        self.assertEqual({r['qualified_name']for r in duplicates['data']['items']},{'One::duplicate','Two::duplicate'})
        alias=self.backend.search(kind='functions',pattern='hidden_alias')
        self.assertEqual(alias['data']['items'][0]['address'],'00000104')
        self.assertEqual(alias['data']['items'][0]['source'],'function_start_candidate')
        class Address(str):
            def getOffset(self):return int(self.split(':')[-1],16)
        external=Mock();external.getEntryPoint.return_value=Address('EXTERNAL:00000104')
        external.getName.side_effect=lambda full=False:'library::duplicate'if full else'duplicate'
        external.getSignature.return_value='external duplicate()';external.getBody.return_value.getNumAddresses.return_value=0
        external.isExternal.return_value=True
        manager=self.backend.program.getFunctionManager.return_value
        manager.getExternalFunctions.return_value=[external,external]
        self.backend.go_functions={'104':{'address':'00000104','name':'go.duplicate'}}
        result=self.backend.search(kind='functions',pattern='duplicate')
        self.assertEqual(result['data']['matches'],3)
        self.assertEqual(sum(r.get('external',False)for r in result['data']['items']),1)
        self.assertIn('external_function',{r['source']for r in result['data']['items']})
        self.assertIn('library::duplicate',{r.get('qualified_name')for r in result['data']['items']})
        self.assertEqual(self.backend.search(kind='functions',pattern='hidden_alias')['data']['items'][0]['address'],'00000104')

    def test_corrupt_counts_are_rejected_without_erasing_evidence(self):
        first=self.backend.search(kind='functions')
        identifier=first['evidence']['id']
        db=self.backend.discovery_index.db
        db.execute('UPDATE state SET position=position+1 WHERE id=1')
        self.backend.invalidate_views()
        with self.assertRaisesRegex(RuntimeError,'incomplete, corrupt or incompatible'):
            self.backend.search(kind='functions')
        self.assertIn(identifier,self.backend.read_evidence(identifier)['text'])

    def test_corrupt_search_names_cannot_silently_hide_candidates(self):
        first=self.backend.search(kind='functions',pattern='00000108')
        self.assertEqual(first['data']['matches'],1)
        identifier=first['evidence']['id'];before=self.backend.read_evidence(identifier)['text']
        self.backend.discovery_index.db.execute("UPDATE candidates SET names='' WHERE position=2")
        with self.assertRaisesRegex(RuntimeError,'corrupt|integrity'):
            self.backend.search(kind='functions',pattern='00000108')
        self.assertEqual(self.backend.read_evidence(identifier)['text'],before)

    def test_corrupt_budget_accounting_and_nonfinite_limits_are_rejected(self):
        first=self.backend.search(kind='functions')
        identifier=first['evidence']['id'];index=self.backend.discovery_index
        original=index.state['bytes']
        for field,value in [('bytes',0),('limits','{"candidates":50000,"seconds":NaN,"bytes":8388608}')]:
            with self.subTest(field=field):
                try:
                    index.db.execute('UPDATE state SET '+field+'=? WHERE id=1',(value,))
                    self.backend.invalidate_views()
                    with self.assertRaisesRegex(RuntimeError,'corrupt|integrity'):
                        self.backend.search(kind='functions')
                    self.assertIn(identifier,self.backend.read_evidence(identifier)['text'])
                finally:
                    import sqlite3
                    self.backend.invalidate_views()
                    with sqlite3.connect(index.path) as db:
                        db.execute('UPDATE state SET bytes=?, limits=? WHERE id=1',
                            (original,function_discovery.canonical({'candidates':50000,'seconds':2,'bytes':8388608})))
                    self.backend.search(kind='functions');index=self.backend.discovery_index

    def test_corrupt_later_or_shadowed_row_cannot_escape_page_integrity_check(self):
        first=self.backend.search(kind='functions',limit=1)
        database=self.backend.discovery_index.db
        for column,value in [('payload','corrupt later payload'),('shadowed',1)]:
            original=database.execute('SELECT '+column+' FROM candidates WHERE position=2').fetchone()[0]
            try:
                database.execute('UPDATE candidates SET '+column+'=? WHERE position=2',(value,))
                with self.subTest(column=column),self.assertRaisesRegex(RuntimeError,'corrupt'):
                    self.backend.search(kind='functions',limit=1,view=first['data']['view'])
            finally:database.execute('UPDATE candidates SET '+column+'=? WHERE position=2',(original,))
        self.assertEqual(self.backend.search(kind='functions',limit=1)['data']['matches'],3)

    def test_full_mode_keeps_offset_pagination_and_refuses_discovery_cursors(self):
        self.backend.analysis_mode='full'
        first=self.backend.search(kind='functions',offset=1)
        self.assertNotIn('view',first['data'])
        self.assertIsNone(self.backend.discovery_index)
        with self.assertRaisesRegex(ValueError,'quick profile'):
            self.backend.search(kind='functions',index_cursor='not-a-token')


class LiteralScope(unittest.TestCase):
    def test_only_initialized_read_only_non_executable_blocks_are_indexed(self):
        def block(start,write=False,execute=False,initialized=True,size=4):
            fake=Mock()
            fake.getSize.return_value=size;fake.getStart.return_value.getOffset.return_value=start
            fake.isInitialized.return_value=initialized;fake.isRead.return_value=True
            fake.isWrite.return_value=write;fake.isExecute.return_value=execute
            return fake
        backend=Mock()
        backend.program.getMemory.return_value.getBlocks.return_value=[
            block(0x10),block(0x20,write=True),block(0x30,execute=True),block(0x40,initialized=False),block(0x50)]
        backend._block_bytes.side_effect=lambda fake,limit:b'abcd'
        with patch('eaos.quick.MAX_LITERAL_BYTES',8):
            selected=quick.literal_blocks(backend)
        self.assertEqual([start for start,_ in selected],[0x10,0x50])


class BoundedFlow(unittest.TestCase):
    def test_body_is_reachable_instructions_not_whole_interval(self):
        instructions={100:(103,[112],104,False,False),104:(107,[],None,True,False),112:(115,[],None,True,False)}
        body,issues=walk(100,128,instructions.get,lambda _:100,{100,128})
        self.assertEqual(body,{100:103,104:107,112:115});self.assertFalse(issues)
        self.assertNotIn(108,body)

    def test_indirect_tail_fallthrough_and_invalid_decode_are_partial(self):
        cases=[((103,[],None,False,True),'Indirect'),((103,[200],None,False,False),'tail'),
               ((103,[],104,False,False),'escapes'),((103,[108],None,False,False),'Missing')]
        for instruction,reason in cases:
            body,issues=walk(100,104 if reason=='escapes'else 120,{100:instruction}.get,lambda _:100,{100,200})
            self.assertTrue(body);self.assertIn(reason,' '.join(issues))

    def test_boundary_and_ownership_refusals(self):
        with self.assertRaisesRegex(ValueError,'crosses'):
            walk(100,102,lambda _: (103,[],None,True,False),lambda _:100,{100})
        with self.assertRaisesRegex(ValueError,'another function'):
            walk(100,120,lambda _: (103,[],None,True,False),lambda _:99,{100})
        with self.assertRaisesRegex(ValueError,'No safely'):
            walk(100,120,lambda _:None,lambda _:None,{100})

    def test_depth_and_instruction_budgets(self):
        def decode(address):return address+3,[address+4],None,False,False
        with patch('eaos.quick.MAX_INSTRUCTIONS',2):
            body,issues=walk(100,200,decode,lambda _:100,{100})
        self.assertEqual(len(body),2);self.assertIn('budget',' '.join(issues))
        with patch('eaos.quick.MAX_BRANCH_DEPTH',0):
            _,issues=walk(100,200,decode,lambda _:100,{100})
        self.assertIn('depth',' '.join(issues))

    def test_raw_and_structured_evidence_remain_immutable(self):
        with tempfile.TemporaryDirectory()as tmp:
            store=Evidence(Path(tmp),'a'*64)
            first=store.artifact('return 1;');second=store.artifact('return 2;')
            self.assertNotEqual(first['uri'],second['uri'])
            a=store.save('inspect','computed',first,provenance={'revision':1})
            b=store.save('inspect','computed',second,provenance={'revision':2})
            self.assertIn('revision',store.read(a['id'])['text']);self.assertNotEqual(a['id'],b['id'])
            before=(Path(tmp)/(a['id']+'.json')).stat().st_mtime_ns
            store.save('inspect','computed',first,provenance={'revision':1})
            self.assertEqual(before,(Path(tmp)/(a['id']+'.json')).stat().st_mtime_ns)


if __name__=='__main__':unittest.main()
