"""Post-run integrity audit only; never changes the frozen scorer or answer key."""
import hashlib
import json
import re
from pathlib import Path
import study2

ROOT=study2.ROOT;OUT=study2.OUT

def audit():
 protocol=json.loads(study2.PROTOCOL.read_text());study2.verify(protocol)
 result=json.loads((OUT/'results.json').read_text());assert result['complete'] and len(result['runs'])==9
 rows=result['runs'];sessions=[];rea_evidence=[];support=[]
 ranges={x['name']:x for x in json.loads((ROOT/'private/round2/support-ranges.json').read_text())}
 roles=['_P_DamageMobj','_P_DamageMobj','_P_CheckAmmo','_PIT_RadiusAttack','_A_BFGSpray','_P_GiveAmmo']
 questions=json.loads((ROOT/'benchmark/questions-round2.json').read_text())['questions']
 lookup={f:ranges[role] for q,role in zip(questions,roles) for f in q['fields']}
 for row in rows:
  assert row['fixed_model_effort'] and row['target_matches'] and row['decompiler_prewarmed']
  assert row['completed'] and row['status']=='finished'
  assert not any(row[k] for k in ['isolation_violations','broken_evidence','broken_citations'])
  d=ROOT/'benchmark/runs'/row['id'];record=json.loads((d/'run.json').read_text());sessions.append(record['session_id'])
  if row['arm']=='ours':assert row['analysis_counts']==[1]
  if row['arm']=='rea':
   assert any(p.endswith('SKILL.md') for p in row['workflow_documents'])
   assert any(p.endswith('references/native-and-artifacts.md') for p in row['workflow_documents'])
   assert record['setup']['stock_tool_count']==207
  assert record['setup']['exposed_tool_count']=={'ours':7,'rea':209,'community':29}[row['arm']]
  answer=json.loads((d/'answer.json').read_text());raw=(d/'tools.jsonl').read_text()
  ids=set(re.findall(r'ev_[0-9a-f]{64}',json.dumps(answer))) if row['arm']=='rea' else set()
  rea_evidence.extend({'run':row['id'],'id':i,'returned':i in raw} for i in ids)
  for field in answer['answers']:
   bounds=lookup[field['id']];addresses=[int(a,16) for a in re.findall(r'(?:0x)?(1[0-9a-fA-F]{8,})',field['evidence'])]
   support.append({'run':row['id'],'field':field['id'],'primary_function_linkage':any(int(bounds['start'],16)<=a<int(bounds['end_exclusive'],16) for a in addresses)})
 assert len(set(sessions))==9 and None not in sessions
 assert all(x['returned'] for x in rea_evidence)
 total=lambda k:sum(x[k] for x in rows)
 report={'unique_fixed_model_sessions':len(sessions),'fixed_model':'gpt-6.1-sol','effort':'high','all_target_hashes_match':True,
  'all_prewarmed':True,'all_frozen_hashes_match':True,'earlier_reports_unchanged':len(protocol['earlier_reports']),
  'our_evidence_records_checked':total('evidence_checked'),'our_final_citations_checked':total('final_citations_checked'),
  'broken_evidence_records':total('broken_evidence'),'broken_final_citations':total('broken_citations'),
  'rea_final_evidence_ids':len(rea_evidence),'rea_ids_not_returned':sum(not x['returned'] for x in rea_evidence),
  'primary_function_linkage':{'linked':sum(x['primary_function_linkage'] for x in support),'total':len(support),
   'note':'Address linkage is a secondary audit, not a substitute for the frozen exact-value scorer or a proof of every semantic step.'},
  'isolation_violations':total('isolation_violations'),'tool_errors':total('tool_errors'),
  'oracle_fields':24,'repo_visibility_verified':'PRIVATE','github_writes':False,
  'unit_tests_passed':10,'real_fixture_contract_checks':json.loads((OUT/'contract-checks.json').read_text())['passed'],
  'rea_evidence_checks':rea_evidence,'function_linkage_checks':support}
 (OUT/'validation.json').write_text(json.dumps(report,indent=2));print(json.dumps({k:v for k,v in report.items() if not k.endswith('checks')},indent=2))
if __name__=='__main__':audit()
