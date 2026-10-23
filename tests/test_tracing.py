import unittest

from eaos.tracing import trace


def edge(source, target, call_site=None):
    return {'source':source, 'target':target, 'call_site':call_site or source+'0',
            'kind':'call', 'classification':'computed'}


def graph_provider(graph, names=None, identity=None):
    def provide(address, direction, limit):
        matches = (graph.get(address, []) if direction == 'callees' else
                   [e for edges in graph.values() for e in edges if e['target'] == address])
        node = {'address':address, 'name':(names or {}).get(address, address)}
        if identity is not None:
            node['identity'] = identity
        return {'node':node, 'edges':matches[:limit], 'complete':len(matches)<=limit}
    return provide


class Tracing(unittest.TestCase):
    def test_cycle_duplicate_names_and_distinct_callsites(self):
        graph={'a':[edge('a','b','a1'),edge('a','b','a2'),edge('a','b','a1')],
               'b':[edge('b','a'),edge('b','c')], 'c':[]}
        result=trace('a',graph_provider(graph,dict(a='duplicate',b='duplicate')))
        self.assertEqual({n['address'] for n in result['nodes']},{'a','b','c'})
        self.assertEqual(len(result['edges']),4)
        self.assertTrue(result['coverage']['traversal_complete'])

    def test_callers_direction_and_component_identity_preserved(self):
        identity={'component':'c1','slice':'arm64'}
        result=trace('b',graph_provider({'a':[edge('a','b')]},identity=identity),direction='callers')
        self.assertEqual([n['address'] for n in result['nodes']],['b','a'])
        self.assertEqual(result['nodes'][0]['identity'],identity)

    def test_depth_zero_reports_relationship_without_traversing(self):
        result=trace('a',graph_provider({'a':[edge('a','b')]}),max_depth=0)
        self.assertEqual(len(result['nodes']),1)
        self.assertEqual(result['frontier'][0]['reason'],'depth_limit')
        self.assertFalse(result['coverage']['traversal_complete'])

    def test_node_and_edge_budgets_retain_frontier(self):
        graph={'a':[edge('a','b'),edge('a','c')],'b':[edge('b','d')]}
        result=trace('a',graph_provider(graph),max_nodes=1)
        self.assertEqual(len(result['nodes']),1)
        self.assertEqual({f['address'] for f in result['frontier']},{'b','c'})
        result=trace('a',graph_provider(graph),max_edges=1)
        self.assertEqual(len(result['edges']),1)
        self.assertFalse(result['coverage']['traversal_complete'])
        self.assertTrue(any(f['reason']=='relationship_enumeration_incomplete' for f in result['frontier']))

    def test_unknown_indirect_and_incomplete_relationships_not_promoted(self):
        def provider(address,direction,limit):
            return {'node':{'address':address},'edges':[edge(address,None)],
                    'unresolved':[{'reason':'objc_dispatch','selector':'value:'}], 'complete':False}
        result=trace('a',provider)
        self.assertEqual(len(result['nodes']),1)
        self.assertEqual({f['reason'] for f in result['frontier']},
                         {'relationship_enumeration_incomplete','objc_dispatch','unresolved_target'})

    def test_time_limit_before_work_and_after_provider(self):
        ticks=iter([0,2,2])
        result=trace('a',lambda *args:self.fail('provider called'),max_seconds=1,clock=lambda:next(ticks))
        self.assertEqual(result['coverage']['stopping_reason'],'time_limit')
        self.assertEqual(result['frontier'][0]['address'],'a')
        ticks=iter([0,0,2,2])
        result=trace('a',graph_provider({'a':[edge('a','b')]}),max_seconds=1,clock=lambda:next(ticks))
        self.assertEqual(result['coverage']['stopping_reason'],'time_limit')

    def test_cancellation_and_provider_failure(self):
        result=trace('a',lambda *args:self.fail('provider called'),cancel=lambda:True)
        self.assertEqual(result['coverage']['stopping_reason'],'cancelled')
        def provider(*args):raise RuntimeError('unavailable component')
        result=trace('a',provider)
        self.assertEqual(result['frontier'][0]['reason'],'provider_failure')
        self.assertIn('unavailable component',result['frontier'][0]['error'])

    def test_provider_cancellation_timeout_and_site_frontier(self):
        for exception, reason in [(InterruptedError, 'cancelled'), (TimeoutError, 'time_limit')]:
            def provider(*args):raise exception('native enumeration stopped')
            result=trace('a',provider)
            self.assertEqual(result['coverage']['stopping_reason'],reason)
            self.assertEqual(result['frontier'][0]['reason'],reason)
        result=trace('a',lambda *args:{'node':{'address':'a'},'edges':[],
            'unresolved':[{'address':'a8','reason':'indirect_call'}], 'complete':True})
        self.assertEqual(result['frontier'][0]['address'],'a8')
        state={'cancelled':False}
        def provider(*args):
            state['cancelled']=True
            return {'node':{'address':'a'},'edges':[], 'complete':True}
        result=trace('a',provider,cancel=lambda:state['cancelled'])
        self.assertEqual(result['coverage']['stopping_reason'],'cancelled')

    def test_provider_cannot_silently_change_identity_or_overrun_limits(self):
        result=trace('a',lambda *args:{'node':{'address':'wrong'},'edges':[],'complete':True})
        self.assertEqual(result['frontier'][0]['reason'],'provider_identity_mismatch')
        result=trace('a',lambda *args:{'node':{'address':'a'},'edges':[edge('a',str(i)) for i in range(5)],'complete':True},per_node_edges=1,max_depth=0)
        self.assertEqual(len(result['edges']),1)
        self.assertTrue(any(f['reason']=='per_node_edge_limit' for f in result['frontier']))

    def test_malformed_contract_bounds(self):
        for arguments in [{'direction':'sideways'},{'max_depth':-1},{'max_depth':9},
                          {'max_nodes':True},{'max_edges':0},{'max_seconds':float('nan')},
                          {'max_seconds':float('inf')},{'per_node_edges':129}]:
            with self.assertRaises(ValueError):trace('a',graph_provider({}),**arguments)
        with self.assertRaises(ValueError):trace('',graph_provider({}))

    def test_malformed_edges_remain_frontier_not_traversed(self):
        result=trace('a',lambda *args:{'node':{'address':'a'},'edges':[
            {'source':'wrong','target':'b','call_site':'a0'}, None], 'complete':True})
        self.assertEqual(result['edges'],[])
        self.assertFalse(result['coverage']['traversal_complete'])

    def test_per_node_unknown_coverage_is_not_promoted_to_complete(self):
        result=trace('a',lambda *args:{'node':{'address':'a'},'edges':[]})
        self.assertIsNone(result['nodes'][0]['relationships']['enumeration_reported_complete'])
        self.assertFalse(result['coverage']['traversal_complete'])
        complete=trace('a',graph_provider({'a':[]}))
        self.assertTrue(complete['nodes'][0]['relationships']['enumeration_reported_complete'])
        partial=trace('a',lambda *args:{'node':{'address':'a'},'edges':[],'complete':False})
        self.assertFalse(partial['nodes'][0]['relationships']['enumeration_reported_complete'])
