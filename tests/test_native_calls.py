from types import SimpleNamespace
import time
import unittest
from unittest.mock import patch
from eaos.native_calls import provider

class Flow:
    def __init__(self,call=False,jump=False,computed=False):self.call,self.jump,self.computed=call,jump,computed
    def isCall(self):return self.call
    def isJump(self):return self.jump
    def isComputed(self):return self.computed
    def isConditional(self):return False

class Body:
    def contains(self,address):return '100'<=address<'200'

class Fn:
    def getEntryPoint(self):return '100'
    def getBody(self):return Body()
    def isExternal(self):return False

class Instruction:
    def __init__(self,address,flow,targets):self.address,self.flow,self.targets=address,flow,targets
    def getAddress(self):return self.address
    def getFlowType(self):return self.flow
    def getFlows(self):return self.targets


def backend(instructions,quick=False):
    fn=Fn();mapping={i.address:i for i in instructions}
    manager=SimpleNamespace(getFunctionContaining=lambda _:fn,getFunctionAt=lambda address:fn if address=='100' else None)
    listing=SimpleNamespace(getInstructions=lambda *_:iter(instructions),getInstructionAt=lambda at:mapping.get(at))
    refs=SimpleNamespace(getReferencesTo=lambda _:[SimpleNamespace(getFromAddress=lambda at=i.address:at) for i in instructions])
    return SimpleNamespace(program=SimpleNamespace(getFunctionManager=lambda:manager,getListing=lambda:listing,getReferenceManager=lambda:refs),
        monitor=None,address=lambda s:s,fn_info=lambda f:{'address':'100','name':'fixture'},
        analysis_mode='quick' if quick else 'full',function_readiness={})

class NativeCallProvider(unittest.TestCase):
    def test_recursion_retained_but_internal_jumps_not_tail_calls(self):
        items=[Instruction('104',Flow(call=True),['100']),Instruction('108',Flow(jump=True),['100'])]
        for direction in ('callees','callers'):
            result=provider(backend(items),time.monotonic()+1)('100',direction,8)
            self.assertEqual(len(result['edges']),1)
            self.assertEqual(result['edges'][0]['kind'],'direct_call')
            self.assertEqual(result['edges'][0]['call_site'],'104')

    def test_outgoing_branch_is_neutral_not_claimed_tail_call(self):
        result=provider(backend([Instruction('104',Flow(jump=True),['300'])]),time.monotonic()+1)('100','callees',8)
        self.assertEqual(result['edges'][0]['kind'],'direct_outgoing_jump')
        self.assertFalse(result['edges'][0]['target_analyzed'])

    def test_indirect_and_unprepared_body_remain_unresolved(self):
        result=provider(backend([Instruction('104',Flow(call=True,computed=True),[])]),time.monotonic()+1)('100','callees',8)
        self.assertEqual(result['edges'],[])
        self.assertFalse(result['complete'])
        self.assertIn('runtime dispatch',result['unresolved'][0]['reason'])
        for quick in (False,True):
            result=provider(backend([],quick),time.monotonic()+1)('100','callees',8)
            self.assertFalse(result['complete'])
            self.assertTrue(any('No recovered instructions' in r['reason'] for r in result['unresolved']))

    def test_deadline_and_cancel_before_native_read(self):
        with self.assertRaises(InterruptedError):provider(backend([]),time.monotonic()+1,lambda:True)('100','callees',8)
        with self.assertRaises(TimeoutError):provider(backend([]),time.monotonic()-1)('100','callees',8)

    def test_inspected_partial_flow_retains_reason_without_preparation_loop(self):
        items=[Instruction('104',Flow(call=True),['300'])]
        for direction in ('callees','callers'):
            for reason in ('Indirect jump unresolved; body incomplete',
                           'Direct tail edge; target signature/control flow not recovered',
                           'Control flow escapes candidate extent; safe complete body unavailable'):
                b=backend(items,quick=True)
                before=provider(b,time.monotonic()+1)('100',direction,8)
                self.assertTrue(any('inspect this function explicitly' in r['reason'] for r in before['unresolved']))
                b.function_readiness['100']={'state':'assembly_partial','limitations':[reason]}
                after=provider(b,time.monotonic()+1)('100',direction,8)
                self.assertFalse(after['complete'])
                self.assertEqual(before['edges'],after['edges'])
                self.assertTrue(any(reason in r['reason'] and 'Use assembly or explicitly choose full analysis' in r['reason'] for r in after['unresolved']))
                self.assertFalse(any('inspect this function explicitly' in r['reason'] for r in after['unresolved']))

    def test_prepared_flow_and_full_analysis_do_not_inherit_partial_guidance(self):
        for quick,state in [(True,'flow_prepared'),(False,'assembly_partial')]:
            b=backend([Instruction('104',Flow(call=True),['300'])],quick=quick)
            b.function_readiness['100']={'state':state,'limitations':['Fixture partial reason']}
            result=provider(b,time.monotonic()+1)('100','callees',8)
            self.assertEqual(result['complete'],not quick)
            self.assertFalse(any('partial assembly' in r['reason'] or 'Fixture partial reason' in r['reason'] for r in result['unresolved']))

    def test_unprepared_candidate_keeps_name_without_indexing_or_preparing(self):
        b = backend([], quick=True)
        b.program.getFunctionManager().getFunctionContaining = lambda _: None
        b.quick_metadata = {'function_starts': [0x100, 0x200]}
        row = {'address':'100','name':'candidate_method','qualified_name':'Class::candidate_method',
               'source':'function_start_candidate','analysis':{'state':'not_prepared'}}
        with patch('eaos.function_discovery.candidate_metadata', return_value=(row,False)) as metadata:
            result = provider(b,time.monotonic()+1)('100','callees',8)
            self.assertEqual(result['node'],row)
            self.assertFalse(result['complete'])
            self.assertEqual(result['edges'],[])
            self.assertIn('No analyzed function',result['unresolved'][0]['reason'])
            metadata.assert_called_once()
        for address,mode in [('101','quick'),('EXTERNAL:100','quick'),('100','full')]:
            b.analysis_mode = mode
            with patch('eaos.function_discovery.candidate_metadata') as metadata:
                result = provider(b,time.monotonic()+1)(address,'callees',8)
                self.assertEqual(result['node'],{'address':address})
                metadata.assert_not_called()

    def test_candidate_metadata_cancellation_uses_trace_cancellation_contract(self):
        b = backend([], quick=True)
        b.program.getFunctionManager().getFunctionContaining = lambda _: None
        b.quick_metadata = {'function_starts': [0x100]}
        calls = 0
        def cancelled():
            nonlocal calls
            calls += 1
            return calls > 1
        def metadata(backend, number, deadline, check):
            check()
            self.fail('Cancelled metadata lookup continued')
        with patch('eaos.function_discovery.candidate_metadata', side_effect=metadata):
            with self.assertRaises(InterruptedError):
                provider(b,time.monotonic()+1,cancelled)('100','callees',8)
