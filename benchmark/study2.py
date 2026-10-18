"""Second frozen study. Preserves every original run and report."""
from pathlib import Path
import argparse
import collections
import datetime
import hashlib
import html
import json
import os
import re
import signal
import statistics
import subprocess
import time
from urllib.parse import unquote,urlparse
import run
from summarize import estimate,events

ROOT=run.ROOT;B=run.BENCH;OUT=ROOT/'reports/round2';PRIVATE=ROOT/'private/round2'
PROTOCOL=B/'protocol-round2.json'

def freeze():
 if PROTOCOL.exists():raise RuntimeError('Already frozen')
 oracle=json.loads((PRIVATE/'oracle-receipt.json').read_text());target=json.loads((PRIVATE/'manifest.json').read_text())
 if run.digest(ROOT/target['target'])!=oracle['target_sha256']:raise RuntimeError('Oracle target mismatch')
 # First recovered function only: generic decompiler warmup, unrelated to questions.
 from eaos.backend import Backend
 backend=Backend(str(ROOT/target['target']))
 try:
  backend._load();first=str(next(iter(backend.program.getFunctionManager().getFunctions(True))).getEntryPoint())
 finally:backend.close()
 paths=[*sorted((ROOT/'src/eaos').glob('*.py')),B/'engine.mjs',B/'relay.py',B/'run.py',B/'study2.py',B/'questions-round2.json',
  B/'answer-schema.json',B/'pricing.json',B/'summarize.py',B/'build_round2.py',B/'oracle_round2.py',B/'check_round2.py',
  PRIVATE/'answer-key.json',PRIVATE/'runtime-oracle.json',PRIVATE/'oracle-receipt.json',ROOT/target['target']]
 skill=B/'installer/home/.agents/skills/reverse-engineer-anything'
 paths.extend(sorted(p for p in skill.rglob('*.md') if p.is_file()))
 catalog_pin=json.loads((B/'community-pin.json').read_text())
 document={'frozen_at':datetime.datetime.now(datetime.UTC).isoformat(),'model':run.MODEL,'effort':run.EFFORT,
  'codex_version':subprocess.check_output(['codex','--version'],text=True).strip(),'target':target,
  'questions':'benchmark/questions-round2.json','questions_per_session':6,'fields_per_session':24,
  'repetitions_per_arm':3,'tool_call_budget':100,'timeout_seconds':900,'warmup_address':first,
  'schedule':[{'arm':arm,'id':f'runs/n{rep+1}{idx+1}'} for rep,order in enumerate([
   ['community','ours','rea'],['rea','community','ours'],['ours','rea','community']]) for idx,arm in enumerate(order)],
  'rea':json.loads((B/'installer/receipt.json').read_text()),'community':catalog_pin,
  'warmup':'Fresh backend per session. Same binary bytes; analyzed readiness plus first recovered-function decompilation for all arms before agent timer. Ours/community copy the same canonical Ghidra project; REA stock imports/analyzes its own copy. Setup measured separately. Warmup answers are not given to agents.',
  'caching':'Model/API cache not flushed or guaranteed prewarmed; fresh sessions with serial Latin-square order. Report measured cached fractions and costs; do not assume identical hit rates.',
  'scoring':'Frozen integer key independently checked by executable gameplay probes. Missing, duplicate or null fields fail. Complete question passes only when all fields match. Report evidence/isolation separately; address occurrence alone is not semantic support.',
  'runtime_boundaries':oracle['boundaries'],
  'limitations':['One privately mutated ARM64 source-built Doom executable, six tasks, three trials per arm. No general superiority claim.',
   'All three use the shared arithmetic calculator. REA full 207 stock tools and installed skill; selected-target static-native guard remains. Normal close_binary cleanup now allowed, correcting the previous harness restriction.',
   'No agent pilots on these questions. Engineering checks use a different tiny fixture. No tool/question/grader changes after freeze.',
   'Oracle tests controlled arithmetic bounds, not reachability of simultaneous extrema in deterministic RNG gameplay. No WAD session.',
   'API-equivalent USD uses recorded aggregate cache categories and pinned rates; actual subscription invoice/per-request tier unknown.'],
  'hashes':{str(p.relative_to(ROOT)):run.digest(p) for p in paths},
  'earlier_reports':{str(p.relative_to(ROOT)):run.digest(p) for p in (ROOT/'reports').iterdir() if p.is_file()}}
 PROTOCOL.write_text(json.dumps(document,indent=2));print('Frozen new six-question/24-field protocol; no agent runs yet.',flush=True)

def verify(protocol):
 for rel,sha in {**protocol['hashes'],**protocol['earlier_reports']}.items():
  if run.digest(ROOT/rel)!=sha:raise RuntimeError('Frozen or earlier file changed: '+rel)
 if (run.MODEL,run.EFFORT)!=('gpt-6.1-sol','high'):raise RuntimeError('Model changed')

def trial(protocol,plan):
 env={**os.environ,'EAOS_STUDY_PROFILE':'round2','EAOS_WARMUP_ADDRESS':protocol['warmup_address']}
 directory,engine,log=run.prepare(plan['arm'],plan['id'],ROOT/protocol['target']['target'],env=env)
 doc=json.loads((B/protocol['questions'].removeprefix('benchmark/')).read_text())
 text=doc['context']+'\n\n'+'\n\n'.join(q['text']+'\nReturn fields: '+', '.join(q['fields'])+'.' for q in doc['questions'])
 text+='\n\nUse at most 100 analysis tool calls, then submit every requested field exactly once. Values must be decimal integers or null for UNKNOWN. Cite concrete virtual addresses and corresponding evidence IDs/links when available. Label deductions computed, observations fact and hypotheses guess. Concise final explanation. Work within the time limit; submit partial verified results rather than inventing missing values.'
 if plan['arm']=='rea':text='Use $reverse-engineer-anything. Read installed SKILL.md and the applicable native guide using read_workflow_document.\n\n'+text
 cmd=run.command(plan['arm'],directory);(directory/'command.json').write_text(json.dumps(cmd,indent=2));(directory/'prompt.txt').write_text(text)
 status='finished';start=time.monotonic()
 try:
  with (directory/'events.jsonl').open('w') as output,(directory/'stderr.log').open('w') as error:
   p=subprocess.Popen(cmd,stdin=subprocess.PIPE,stdout=output,stderr=error,text=True,start_new_session=True)
   try:p.communicate(text,timeout=protocol['timeout_seconds'])
   except subprocess.TimeoutExpired:
    status='timeout';os.killpg(p.pid,signal.SIGTERM)
    try:p.wait(timeout=8)
    except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
  elapsed=time.monotonic()-start
 finally:run.cleanup(engine,log)
 ev=events(directory/'events.jsonl');usage=next((e['usage'] for e in reversed(ev) if e.get('type')=='turn.completed'),None)
 record={'stage':'round2','run_id':plan['id'],'arm':plan['arm'],'model':run.MODEL,'effort':run.EFFORT,
  'session_id':next((e.get('thread_id') for e in ev if e.get('type')=='thread.started'),None),
  'status':status,'exit_code':p.returncode,'agent_seconds':elapsed,'usage':usage,
  'setup':json.loads((directory/'ready.json').read_text()),'completed':any(e.get('type')=='turn.completed' for e in ev),
  'answer_saved':(directory/'answer.json').exists()}
 (directory/'run.json').write_text(json.dumps(record,indent=2));print(json.dumps(record),flush=True)
 return record

def execute():
 protocol=json.loads(PROTOCOL.read_text());verify(protocol)
 for plan in protocol['schedule']:
  directory=B/plan['id']
  if (directory/'run.json').exists():continue
  if directory.exists():raise RuntimeError('Partial setup/run retained; inspect rather than overwrite: '+str(directory))
  verify(protocol)
  try:trial(protocol,plan)
  except Exception as exc:
   directory.mkdir(exist_ok=True,parents=True)
   (directory/'run.json').write_text(json.dumps({'stage':'round2',**plan,'run_id':plan['id'],'model':run.MODEL,'effort':run.EFFORT,'status':'setup_error','error':str(exc),'usage':None},indent=2))
   print(json.dumps({'setup_error':str(exc),'run_id':plan['id']}),flush=True)
 verify(protocol)


def report():
 protocol=json.loads(PROTOCOL.read_text());verify(protocol)
 key=json.loads((PRIVATE/'answer-key.json').read_text());questions=json.loads((B/'questions-round2.json').read_text())['questions']
 pricing=json.loads((B/'pricing.json').read_text());rows=[];reviews=[];sessions=set();counts=collections.Counter();profiles={}
 for plan in protocol['schedule']:
  d=B/plan['id']
  if not (d/'run.json').exists():continue
  r=json.loads((d/'run.json').read_text());answer=json.loads((d/'answer.json').read_text()) if (d/'answer.json').exists() else {'answers':[]}
  fields=answer.get('answers',[]);duplicates=collections.Counter(a['id'] for a in fields);byid={a['id']:a for a in fields}
  matches={k:duplicates[k]==1 and byid[k].get('value')==v and type(byid[k].get('value')) is int for k,v in key.items()}
  calls=events(d/'tools.jsonl');success=[c for c in calls if c.get('event')=='call' and not c.get('isError')]
  text='\n'.join(json.dumps(c['result']) for c in success);evidence_checks=[];citations=[]
  for c in success:
   pk=r['arm']+':'+c['name'];v=profiles.setdefault(pk,{'calls':0,'result_bytes':0,'tool_ms':0});v['calls']+=1;v['result_bytes']+=c['result_bytes'];v['tool_ms']+=c['elapsed_ms']
   if r['arm']=='ours':
    for block in c['result'].get('content',[]):
     if block.get('type')!='text':continue
     try:payload=json.loads(block['text'])
     except ValueError:continue
     if 'evidence' not in payload:continue
     e=payload['evidence'];p=Path(unquote(urlparse(e['uri']).path))
     valid=p.is_file() and p.with_suffix('.sha256').is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==p.with_suffix('.sha256').read_text().strip()
     evidence_checks.append({'id':e['id'],'valid':valid,'uri':e['uri']})
  if r['arm']=='ours':
   seen={x['id'] for x in evidence_checks};final=json.dumps(answer)
   for identifier in sorted(set(re.findall(r'(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])',final))):citations.append({'id':identifier,'valid':identifier in seen})
   for uri in set(re.findall(r'file://[^\s"<>\[\]()]+',final)):
    uri=uri.rstrip('.,;:');citations.append({'uri':uri,'valid':Path(unquote(urlparse(uri).path)).is_file()})
  violations=[]
  for e in events(d/'events.jsonl'):
   item=e.get('item',{});kind=item.get('type')
   if kind in ['command_execution','web_search','file_change'] or (kind=='mcp_tool_call' and item.get('server')!='analysis'):violations.append(item)
  docs=[c.get('arguments',{}).get('path') for c in success if c['name']=='read_workflow_document']
  u=r.get('usage');session=r.get('session_id')
  if session in sessions:raise AssertionError('Session reused')
  if session:sessions.add(session)
  command=json.loads((d/'command.json').read_text()) if (d/'command.json').exists() else []
  fixed=('-m' in command and command[command.index('-m')+1]=='gpt-6.1-sol' and 'model_reasoning_effort="high"' in command)
  cache=list((d/'target/eaos-analysis').glob('*/analysis.json')) if r['arm']=='ours' else []
  analysis_counts=[json.loads(p.read_text()).get('analysis_count') for p in cache]
  row={'id':d.name,'arm':r['arm'],'status':r['status'],'completed':r.get('completed',False),
   'fields_correct':sum(matches.values()),'fields':len(key),'questions_correct':sum(all(matches[f] for f in q['fields']) for q in questions),'questions':len(questions),
   'agent_seconds':r.get('agent_seconds'),'setup_seconds':r.get('setup',{}).get('setup_seconds'),
   'input_tokens':u['input_tokens'] if u else None,'cached_input_tokens':u.get('cached_input_tokens',0) if u else None,'output_tokens':u['output_tokens'] if u else None,
   'total_tokens':u['input_tokens']+u['output_tokens'] if u else None,
   'api_usd':estimate(u,pricing['standard_short_per_million']),'all_long_usd':estimate(u,pricing['standard_long_per_million']),
   'tool_calls':sum(c.get('event')=='call' for c in calls),'tool_errors':sum(c.get('isError',False) or c.get('event')=='error' for c in calls),
   'isolation_violations':len(violations),'evidence_checked':len(evidence_checks),'broken_evidence':sum(not x['valid'] for x in evidence_checks),
   'final_citations_checked':len(citations),'broken_citations':sum(not x['valid'] for x in citations),'workflow_documents':docs,
   'fixed_model_effort':fixed,'target_matches':run.digest(d/'target/chocolate-doom-round2')==protocol['target']['sha256'],'analysis_counts':analysis_counts,
   'decompiler_prewarmed':(d/'decompiler-warmup.json').exists()}
  rows.append(row);reviews.append({'run':row,'answer':answer,'fields':[{'id':k,'expected':v,'answer':byid.get(k),'correct':matches[k],
   'cited_addresses_in_successful_results':[a for a in re.findall(r'(?:0x)?(1[0-9a-fA-F]{8,})',byid.get(k,{}).get('evidence','')) if a.lower() in text.lower()]} for k,v in key.items()],
   'evidence_checks':evidence_checks,'citation_checks':citations,'violations':violations})
 groups=[]
 for arm in ['ours','rea','community']:
  rs=[r for r in rows if r['arm']==arm];available=[r for r in rs if r['api_usd'] is not None]
  if not rs:continue
  g={'arm':arm,'runs':len(rs),'completed':sum(r['completed'] for r in rs),'fields_correct':sum(r['fields_correct'] for r in rs),'fields':sum(r['fields'] for r in rs),
   'questions_correct':sum(r['questions_correct'] for r in rs),'questions':sum(r['questions'] for r in rs),
   'median_seconds':statistics.median(r['agent_seconds'] for r in rs if r['agent_seconds'] is not None),
   'median_setup_seconds':statistics.median(r['setup_seconds'] for r in rs if r['setup_seconds'] is not None),
   **{k:sum(r[k] for r in available) for k in ['total_tokens','input_tokens','cached_input_tokens','output_tokens','api_usd','all_long_usd']},
   'median_tokens':statistics.median(r['total_tokens'] for r in available) if available else None,
   'median_api_usd':statistics.median(r['api_usd'] for r in available) if available else None,
   'missing_usage':len(rs)-len(available)}
  g['cached_fraction']=g['cached_input_tokens']/g['input_tokens'] if g['input_tokens'] else None;groups.append(g)
 payload={'protocol':str(PROTOCOL.relative_to(ROOT)),'model':run.MODEL,'effort':run.EFFORT,'groups':groups,'runs':rows,'pricing':pricing,
  'limits':protocol['limitations'],'complete':len(rows)==9 and all(r['completed'] for r in rows)}
 (OUT/'results.json').write_text(json.dumps(payload,indent=2));(OUT/'answer-review.json').write_text(json.dumps(reviews,indent=2));(OUT/'tool-profile.json').write_text(json.dumps(profiles,indent=2))
 lines=['# New Doom control-flow comparison','','Model **gpt-6.1-sol**, effort **high**. Three fresh sessions per arm; six new tasks and 24 scored fields per session. Separate privately modified build. Earlier results remain unchanged.','',
  '| Tool | Correct questions | Correct fields | Median agent time | Median tokens | Total tokens (3 runs) | API-equivalent USD (3 runs) |',
  '|---|---:|---:|---:|---:|---:|---:|']
 for g in groups:lines.append(f"| {g['arm']} | {g['questions_correct']}/{g['questions']} | {g['fields_correct']}/{g['fields']} | {g['median_seconds']:.1f}s | {g['median_tokens']:,.0f} | {g['total_tokens']:,} | ${g['api_usd']:.4f} |")
 lines+=['','API-equivalent estimates include discounted cached input. Actual Codex subscription billing is unavailable. Standard short-context rates are pinned in benchmark/pricing.json; all-long sensitivity is recorded in results.json.',
  '','Timing includes agent startup, reasoning, tool use and final answer. Initial analysis and identical first-function decompiler warmup occur before timing; setup is reported separately. Model prompt cache is uncontrolled and measured, with counterbalanced serial order.',
  '','Changes: compact evidence envelope; full content-checked records retained; memory defaults to hex with explicit UTF-8/both; call graphs requested explicitly; compact search references/full metadata option; deterministic content IDs and sorted call lists; shorter descriptions.',
  '','No claim of better decompilation or general superiority. Missing/null/duplicate fields fail. Evidence validity and answer correctness are separate checks. See answer-review.json for each answer, expected value and evidence.',
  '','## Individual trials','','| ID | Tool | Questions | Fields | Seconds | Input | Cached | Output | API USD |','|---|---|---:|---:|---:|---:|---:|---:|---:|']
 for r in rows:lines.append(f"| {r['id']} | {r['arm']} | {r['questions_correct']}/6 | {r['fields_correct']}/24 | {r['agent_seconds']:.1f} | {r['input_tokens']:,} | {r['cached_input_tokens']:,} | {r['output_tokens']:,} | ${r['api_usd']:.4f} |")
 (OUT/'results.md').write_text('\n'.join(lines)+'\n')
 # Self-contained local view without external resources.
 head='<!doctype html><meta charset="utf-8"><title>EAOS · new Doom comparison</title><style>body{font:16px system-ui;max-width:1150px;margin:50px auto;padding:0 25px;background:#f6f4ee;color:#20241e}table{border-collapse:collapse;width:100%;margin:25px 0}td,th{padding:12px;border-bottom:1px solid #ccc;text-align:left}h1{font-size:38px}pre{white-space:pre-wrap;line-height:1.6}a{color:#305d45}</style><h1>New Doom control-flow comparison</h1><p>gpt-6.1-sol · high effort · private · 3 fresh runs per tool</p>'
 table='<table><tr>'+''.join('<th>'+x+'</th>' for x in ['Tool','Questions','Fields','Median time','Tokens, total','API USD, total'])+'</tr>'
 for g in groups:table+='<tr>'+''.join('<td>'+html.escape(str(x))+'</td>' for x in [g['arm'],f"{g['questions_correct']}/{g['questions']}",f"{g['fields_correct']}/{g['fields']}",f"{g['median_seconds']:.1f}s",f"{g['total_tokens']:,}",f"${g['api_usd']:.4f}"])+'</tr>'
 (OUT/'results.html').write_text(head+table+'</table><p><a href="../results.html">Earlier study</a> · <a href="results.json">Raw results</a> · <a href="answer-review.json">Answer-by-answer review</a></p><pre>'+html.escape('\n'.join(lines[8:]))+'</pre>')
 print(json.dumps({'groups':groups,'completed':payload['complete']},indent=2))

if __name__=='__main__':
 p=argparse.ArgumentParser();p.add_argument('action',choices=['freeze','run','report']);a=p.parse_args()
 {'freeze':freeze,'run':execute,'report':report}[a.action]()
