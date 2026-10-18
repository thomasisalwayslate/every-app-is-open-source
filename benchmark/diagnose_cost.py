"""Measured old-round billing and payload breakdown; no model calls."""
from pathlib import Path
import json
from summarize import ROOT,estimate,events

def diagnose():
 groups={};runs=[]
 pricing=json.loads((ROOT/'benchmark/pricing.json').read_text())['standard_short_per_million']
 for arm in ['ours','community']:
  usage={k:0 for k in ['input_tokens','cached_input_tokens','cache_write_input_tokens','output_tokens']}; calls=[];metadata=graphs=pseudocode=0
  for d in sorted((ROOT/'benchmark/runs').glob('c*')):
   r=json.loads((d/'run.json').read_text())
   if r['arm']!=arm:continue
   for k in usage:usage[k]+=r['usage'].get(k,0)
   cs=[c for c in events(d/'tools.jsonl') if c.get('event')=='call'];calls+=cs
   catalog=json.loads((d/'catalog.json').read_text())
   runs.append({'id':d.name,'arm':arm,'usage':r['usage'],'calls':len(cs),'result_bytes':sum(c['result_bytes'] for c in cs),'call_order':[c['name'] for c in cs]})
   if arm=='ours':
    for c in cs:
     if c['isError']:continue
     v=json.loads(c['result']['content'][0]['text']);metadata+=len(json.dumps(v.get('evidence',{})).encode())
     if c['name']=='inspect':
      for row in v['data']:
       graphs+=sum(len(json.dumps(row.get(k,[])).encode()) for k in ['callers','callees']);pseudocode+=len(row.get('pseudocode','').encode())
  uncached=usage['input_tokens']-usage['cached_input_tokens']-usage['cache_write_input_tokens']
  groups[arm]={'usage':usage,'uncached_input':uncached,'cached_fraction':usage['cached_input_tokens']/usage['input_tokens'],
    'cost_usd':estimate(usage,pricing),'calls':len(calls),'result_bytes':sum(c['result_bytes'] for c in calls),
    'catalog_bytes_compact':len(json.dumps(catalog,separators=(',',':')).encode()),'description_bytes':sum(len(t.get('description','').encode()) for t in catalog),
    'evidence_metadata_bytes':metadata,'inspect_graph_bytes':graphs,'inspect_pseudocode_bytes':pseudocode}
 a,b=groups['ours'],groups['community']
 delta={'uncached_input_usd':(a['uncached_input']-b['uncached_input'])*pricing['input']/1e6,
  'cached_input_usd':(a['usage']['cached_input_tokens']-b['usage']['cached_input_tokens'])*pricing['cached_input']/1e6,
  'output_usd':(a['usage']['output_tokens']-b['usage']['output_tokens'])*pricing['output']/1e6}
 report={'round':'real-clean, c11..c33','groups':groups,'delta_usd':delta,'runs':runs,
  'limits':['Byte sizes are measured, not tokenizer counts. CLI only records aggregate usage; cache misses cannot be causally assigned to specific fields/turns.',
   'Serial Latin-square order counterbalanced position; cache locality, server routing and request timing are uncontrolled. Output ordering is a reproducibility opportunity, not proven cache-miss attribution.',
   'Ours has a smaller catalog and fewer calls/results overall. Uncached-input billing, not gross token count, explains the measured cost penalty.'],
  'diagnosis_reported_before_edits':True,'changes':'Remove duplicated envelope metadata; default memory hex only; call graph on explicit request; compact search refs; stable evidence IDs and sorted calls; retain full evidence and full/detail modes.'}
 out=ROOT/'reports/round2';out.mkdir(exist_ok=True);(out/'diagnosis.json').write_text(json.dumps(report,indent=2))
 print(json.dumps({'groups':groups,'delta_usd':delta},indent=2))
if __name__=='__main__':diagnose()
