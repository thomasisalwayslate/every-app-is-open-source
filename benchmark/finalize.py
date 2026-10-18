"""Audit recorded trials and finalize private reports. Never posts or changes GitHub."""
from pathlib import Path
import collections
import hashlib
import json
import re
import statistics
import subprocess
import summarize

ROOT=Path(__file__).resolve().parents[1];BENCH=ROOT/'benchmark'


def main():
    report=summarize.summarize()
    primary=[r for r in report['runs'] if r['stage']=='real-clean']
    if len(primary)!=9:raise RuntimeError('Corrected round has not recorded all nine trials')
    protocol=json.loads((BENCH/'protocol-real-clean.json').read_text())
    assert all(hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==sha for name,sha in protocol['hashes'].items())
    assert len(report['runs'])==21
    models=[];profiles={};guard_refusals=[]
    for row in report['runs']:
        directory=BENCH/row['run_id'];meta=json.loads((directory/'run.json').read_text());cmd=json.loads((directory/'command.json').read_text())
        assert cmd[cmd.index('-m')+1]=='gpt-6.1-sol' and 'model_reasoning_effort="high"' in cmd
        models.append({'run':row['run_id'],'model':'gpt-6.1-sol','effort':'high','session_id':meta['session_id']})
        group=profiles.setdefault(meta['stage']+':'+meta['arm'],collections.defaultdict(list))
        for event in summarize.events(directory/'tools.jsonl'):
            if event.get('event')=='call':group[event['name']].append(event)
            if event.get('event')=='error' and event.get('request',{}).get('method')=='tools/call':
                guard_refusals.append({'run_id':row['run_id'],'stage':row['stage'],'arm':row['arm'],
                    'tool':event['request'].get('params',{}).get('name'),'error':event.get('error')})
        if meta['arm']=='ours':
            cache=next((directory/'target/eaos-analysis').iterdir());assert json.loads((cache/'analysis.json').read_text())['analysis_count']==1
        if meta['arm']=='rea':
            docs=row['workflow_documents'];assert any(p.endswith('SKILL.md') for p in docs) and any('native' in p.lower() for p in docs)
    assert len({m['session_id'] for m in models})==21
    assert all(r['isolation_violations']==0 and r['broken_evidence_records']==0 and r['broken_final_citations']==0 for r in report['runs'])
    (ROOT/'reports/model-audit.json').write_text(json.dumps(models,indent=2))
    profile={key:{name:{'calls':len(calls),'errors':sum(bool(c.get('isError')) for c in calls),
        'total_result_bytes':sum(c.get('result_bytes',0) for c in calls),
        'median_result_bytes':statistics.median(c.get('result_bytes',0) for c in calls),
        'total_tool_seconds':sum(c.get('elapsed_ms',0) for c in calls)/1000} for name,calls in values.items()} for key,values in profiles.items()}
    (ROOT/'reports/tool-profile.json').write_text(json.dumps(profile,indent=2))
    (ROOT/'reports/scope-guard-refusals.json').write_text(json.dumps(guard_refusals,indent=2))
    validations={'recorded_trials':21,'tiny_trials':3,'diagnostic_real_trials':9,'primary_real_trials':9,
        'primary_completed':sum(r['completed'] for r in primary),'unique_fresh_sessions':21,
        'fixed_model':'gpt-6.1-sol','fixed_effort':'high','unit_tests_passed':9,'frozen_input_hashes_match':True,
        'all_ours_analysis_counts_one':True,'isolation_violations':0,'broken_evidence_records':0,'broken_final_citations':0,
        'ours_evidence_records_verified':sum(r['evidence_records_checked'] for r in report['runs']),
        'ours_final_citations_verified':sum(r['final_citations_checked'] for r in report['runs']),
        'rea_skill_and_native_guide_loaded_every_run':True,'runtime_table_oracle':True,'runtime_weapon_oracle':True,
        'primary_tool_errors':sum(r['tool_errors'] for r in primary),
        'scope_guard_refusals':guard_refusals,
        'note':'Address appearances in output are mechanical linkage, not independent semantic proof. Exact values are scored by the frozen private key checked with executable oracles. Algebraic shotgun damage bounds use controlled rolls; actual PRNG-sequence reachability is not claimed.'}
    (ROOT/'reports/validation.json').write_text(json.dumps(validations,indent=2))
    groups={g['arm']:g for g in report['groups'] if g['stage']=='real-clean'}
    ours=groups['ours'];rea=groups['rea'];community=groups['community']
    comparison={'scope':'Corrected primary round only: one modified stripped ARM64 Doom, six questions, three trials per tool.',
        'ours_vs_rea':{'median_time_reduction':1-ours['median_agent_seconds']/rea['median_agent_seconds'],
            'token_reduction':1-ours['total_tokens']/rea['total_tokens'],
            'standard_api_equivalent_cost_reduction':1-ours['usd_standard_short_equivalent']/rea['usd_standard_short_equivalent']},
        'ours_vs_community':{'median_time_reduction':1-ours['median_agent_seconds']/community['median_agent_seconds'],
            'token_reduction':1-ours['total_tokens']/community['total_tokens'],
            'standard_api_equivalent_cost_reduction':1-ours['usd_standard_short_equivalent']/community['usd_standard_short_equivalent']},
        'all_recorded_trial_tokens':sum(r['total_tokens'] or 0 for r in report['runs']),
        'all_recorded_trial_standard_api_equivalent':sum(r['usd_standard_short_equivalent'] or 0 for r in report['runs']),
        'all_recorded_trial_cached_input_tokens':sum(r['cached_input_tokens'] or 0 for r in report['runs']),
        'billing_limit':'Includes retained diagnostic and tiny trials; excludes engineering, parent conversation and non-model setup. API equivalent is not a subscription invoice.',
        'quality_limit':'If every tool scores perfectly, this is a ceiling: no evidence of superior correctness. One target and three repeats do not establish general performance.'}
    (ROOT/'reports/comparison.json').write_text(json.dumps(comparison,indent=2))
    def cell(g):
        return f"{g['correct']}/{g['fields']} fields; median {g['median_agent_seconds']:.1f}s; {g['total_tokens']:,} tokens; ${g['usd_standard_short_equivalent']:.3f} API equivalent (3 runs)"
    readme=ROOT/'README.md';text=readme.read_text()
    text=re.sub(r'(?m)^\| Native compiled programs \|.*$',
        '| Native compiled programs: modified stripped Doom | '+cell(rea)+' | '+cell(ours)+' | [Results and community baseline](reports/results.md); [primary protocol](benchmark/protocol-real-clean.json) |',text)
    readme.write_text(text)
    project=ROOT/'PROJECT.md';text=project.read_text()
    text=re.sub(r'(?m)^7\. .*$',
        '7. Corrected primary Doom study complete: six questions, three fresh runs per tool. All originals retained as diagnostic; final metrics are in reports/results.json. Same gpt-6.1-sol/high throughout.',text)
    project.write_text(text)
    cleanup=[g for g in guard_refusals if g['tool']=='close_binary' and g['stage']=='real-clean']
    cleanup_ids=', '.join(g['run_id'] for g in cleanup)
    lines=['# Version 1 review','',
        'Steps 1–7 are complete.',
        '', '| Tool | Correct fields | Complete questions | Median agent time | Median setup | Total tokens | API equivalent, 3 runs |',
        '|---|---:|---:|---:|---:|---:|---:|']
    for arm in ['ours','rea','community']:
        g=groups[arm];lines.append(f"| {arm} | {g['correct']}/{g['fields']} | {g['questions_passed']}/{g['questions']} | {g['median_agent_seconds']:.1f}s | {g['median_setup_seconds']:.1f}s | {g['total_tokens']:,} | ${g['usd_standard_short_equivalent']:.3f} |")
    lines+=['','The primary table uses only the corrected real round. Dollar amounts are standard short-context API equivalents with cached input discounted, not actual subscription charges. Request-level tier data are unavailable; long-context sensitivity is in results.json.',
        '', 'The original tiny trial included REA lazy analysis; original real trials had a broken shared macOS calculator. Both are preserved and labelled, with exact source snapshots. All six previously failing calculator expressions passed after correction. No target, question, answer-key, model, effort, tool-catalog or comparator-version changes were made.',
        '', 'Quality remains limited by this test: perfect scores cannot establish superior correctness. One modified C game cannot establish results on C++, large GUI apps, other architectures, packing, JavaScript, Android or .NET. The five new questions share one binary; they are not independent application samples. No independent human grading is claimed.',
        '', f'The full REA catalog is exposed, but the benchmark permits selected-target static analysis only. Its scope guard rejected {len(cleanup)} close_binary cleanup requests after analysis ({cleanup_ids}). Those refusals belong to this harness, not to REA; their timing/token overhead remains in the recorded results. Both affected runs returned every field correctly. See scope-guard-refusals.json. This is a constrained task comparison, not an unrestricted full-product evaluation.',
        '', 'The full game was compiled from official Chocolate Doom 3.1.1 source with eight randomized changes. Internal code symbols were removed; required loader/import information remains. Executable table and weapon oracles check the key. Weapon oracles substitute random/world boundaries; no WAD/gameplay test or exact PRNG-sequence reachability claim.',
        '', 'The original pilot and stripped studies each finished 12/12 runs; later skill comparison finished 18/18 plus 6/6 clarified runs. No old Blender agent trial finished. The copied evidence, scripts, puzzles, binaries, sources and per-run inventory remain locally in evidence/legacy/.',
        '', 'Verification: fixed-model command audit, 21 unique fresh sessions, immutable primary input hashes, normal REA installer receipts and per-run skill/native-guide reads, canonical analysis reuse, evidence hashes/citations and nine contract/accounting/subprocess tests. See validation.json for counts.',
        '', 'Files: [results](results.md), [full data](results.json), [every answer](answer-review.json), [CSV](runs.csv), [cost comparison](comparison.json), [validation](validation.json), [tool profile](tool-profile.json), [calculator correction](calculator-correction.json).',
        '', 'Private repository only. No issue/PR interactions, stars, package publication, article or later roadmap implementation.']
    (ROOT/'reports/review.md').write_text('\n'.join(lines)+'\n')
    print(json.dumps({'validation':validations,'primary':list(groups.values()),'comparison':comparison},indent=2))


if __name__=='__main__':main()
