"""Deterministic scoring and local reports. Does not call a model or GitHub."""
from pathlib import Path
import collections
import csv
import hashlib
import html
import json
import re
import statistics
from urllib.parse import urlparse,unquote

ROOT=Path(__file__).resolve().parents[1];BENCH=ROOT/'benchmark'


def estimate(usage,rates):
    if usage is None:return None
    i=usage['input_tokens'];c=usage.get('cached_input_tokens',0);w=usage.get('cache_write_input_tokens',0);o=usage['output_tokens']
    if c+w>i:raise ValueError('Cache categories exceed input; cannot price without clarification')
    return ((i-c-w)*rates['input']+c*rates['cached_input']+w*rates['cache_write']+o*rates['output'])/1e6


def events(path):
    result=[]
    if not path.exists():return result
    for line in path.read_text().splitlines():
        try:result.append(json.loads(line))
        except ValueError:pass
    return result


def summarize():
    key=json.loads((ROOT/'private/doom/answer-key.json').read_text())
    questions=json.loads((BENCH/'questions.json').read_text())['questions']
    pricing=json.loads((BENCH/'pricing.json').read_text())
    rows=[];details=[]
    for file in sorted((BENCH/'runs').glob('*/run.json')):
        run=json.loads(file.read_text());directory=file.parent
        relevant=questions[:1] if run['stage']=='tiny' else questions
        wanted=[field for q in relevant for field in q['fields']]
        try:answer=json.loads((directory/'answer.json').read_text())
        except (ValueError,FileNotFoundError):answer={'answers':[],'explanation':'No valid final answer saved.'}
        answers=answer.get('answers',[]);counts=collections.Counter(a.get('id') for a in answers)
        by_id={a.get('id'):a for a in answers};matches={field:counts[field]==1 and type(by_id[field].get('value')) is int and by_id[field]['value']==key[field] for field in wanted}
        calls=events(directory/'tools.jsonl');successful=[e for e in calls if e.get('event')=='call' and not e.get('isError')]
        output_text='\n'.join(json.dumps(e.get('result',{})) for e in successful)
        eventlog=events(directory/'events.jsonl');violations=[]
        for event in eventlog:
            item=event.get('item',{});kind=item.get('type')
            if kind=='mcp_tool_call' and item.get('server')!='analysis':violations.append(item)
            if kind in {'command_execution','web_search','file_change'}:violations.append(item)
        fields=[]
        for field in wanted:
            a=by_id.get(field,{})
            addresses=re.findall(r'(?<![\w])(?:0x)?(1[0-9a-fA-F]{8,})(?![\w])',a.get('evidence',''))
            addresses_seen=[addr for addr in addresses if addr.lower() in output_text.lower()]
            fields.append({'id':field,'expected':key[field],'answer':a.get('value'),'correct':matches[field],
                'classification':a.get('classification'),'evidence':a.get('evidence',''),
                'cited_addresses_seen_in_successful_tools':addresses_seen})
        evidence_checks=[]
        if run['arm']=='ours':
            for call in successful:
                for block in call.get('result',{}).get('content',[]):
                    if block.get('type')!='text':continue
                    try:payload=json.loads(block['text'])
                    except ValueError:continue
                    evidence=payload.get('evidence')
                    if evidence:
                        p=Path(evidence['path']);valid=p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest()==evidence['sha256']
                        evidence_checks.append({'id':evidence['id'],'valid':valid,'path':str(p)})
        final_citations=[]
        if run['arm']=='ours':
            text=json.dumps(answer,ensure_ascii=False)
            seen={e['id'] for e in evidence_checks}
            for identifier in sorted(set(re.findall(r'(?<![0-9a-f])[0-9a-f]{32}(?![0-9a-f])',text))):
                final_citations.append({'kind':'evidence_id','value':identifier,'valid':identifier in seen})
            for uri in sorted(set(re.findall(r'file://[^\s"<>\[\]()]+',text))):
                uri=uri.rstrip('.,;:')
                final_citations.append({'kind':'file_uri','value':uri,'valid':Path(unquote(urlparse(uri).path)).is_file()})
        docs=[e.get('arguments',{}).get('path','') for e in calls if e.get('event')=='call' and e.get('name')=='read_workflow_document' and not e.get('isError')]
        usage=run.get('usage');setup=run.get('setup',{})
        row={'stage':run['stage'],'run_id':run['run_id'],'arm':run['arm'],'status':run['status'],
            'completed':run.get('completed',False),'correct':sum(matches.values()),'fields':len(wanted),
            'questions_passed':sum(all(matches[f] for f in q['fields']) for q in relevant),
            'questions':len(relevant),'full_pass':all(matches.values()),'agent_seconds':run.get('agent_seconds'),
            'setup_seconds':setup.get('setup_seconds'),'tool_calls':sum(e.get('event')=='call' for e in calls),
            'tool_errors':sum(e.get('isError',False) for e in calls)+sum(e.get('event')=='error' for e in calls),
            'input_tokens':usage['input_tokens'] if usage else None,'cached_input_tokens':usage.get('cached_input_tokens',0) if usage else None,
            'output_tokens':usage['output_tokens'] if usage else None,
            'total_tokens':usage['input_tokens']+usage['output_tokens'] if usage else None,
            'usd_standard_short_equivalent':estimate(usage,pricing['standard_short_per_million']),
            'usd_all_long_sensitivity':estimate(usage,pricing['standard_long_per_million']),
            'workflow_documents':docs,'isolation_violations':len(violations),
            'evidence_records_checked':len(evidence_checks),'broken_evidence_records':sum(not e['valid'] for e in evidence_checks),
            'final_citations_checked':len(final_citations),'broken_final_citations':sum(not e['valid'] for e in final_citations)}
        rows.append(row);details.append({'run':row,'fields':fields,'answer':answer,'evidence_checks':evidence_checks,'final_citation_checks':final_citations,'isolation_violations':violations})
    groups=[]
    for stage in ['tiny','real','real-clean']:
        for arm in ['ours','rea','community']:
            subset=[r for r in rows if r['stage']==stage and r['arm']==arm]
            if not subset:continue
            available=[r for r in subset if r['total_tokens'] is not None]
            times=[r['agent_seconds'] for r in subset if r['agent_seconds'] is not None]
            setups=[r['setup_seconds'] for r in subset if r['setup_seconds'] is not None]
            group={'stage':stage,'arm':arm,'runs':len(subset),'completed':sum(r['completed'] for r in subset),
                'correct':sum(r['correct'] for r in subset),'fields':sum(r['fields'] for r in subset),
                'questions_passed':sum(r['questions_passed'] for r in subset),'questions':sum(r['questions'] for r in subset),
                'full_passes':sum(r['full_pass'] for r in subset),
                'median_agent_seconds':statistics.median(times) if times else None,
                'median_setup_seconds':statistics.median(setups) if setups else None,
                'input_tokens':sum(r['input_tokens'] for r in available),'cached_input_tokens':sum(r['cached_input_tokens'] for r in available),
                'output_tokens':sum(r['output_tokens'] for r in available),'total_tokens':sum(r['total_tokens'] for r in available),
                'usd_standard_short_equivalent':sum(r['usd_standard_short_equivalent'] for r in available),
                'usd_all_long_sensitivity':sum(r['usd_all_long_sensitivity'] for r in available),
                'runs_with_unavailable_usage':len(subset)-len(available),'tool_errors':sum(r['tool_errors'] for r in subset),
                'isolation_violations':sum(r['isolation_violations'] for r in subset),
                'broken_evidence_records':sum(r['broken_evidence_records'] for r in subset),
                'broken_final_citations':sum(r['broken_final_citations'] for r in subset)}
            groups.append(group)
    groups.sort(key=lambda g:({'real-clean':0,'tiny':1,'real':2}[g['stage']],{'ours':0,'rea':1,'community':2}[g['arm']]))
    report={'model':'gpt-6.1-sol','effort':'high','groups':groups,'runs':rows,'pricing':pricing,
        'scoring_note':'Address occurrence is only a mechanical linkage check, not proof of the cited address semantically supporting a claim. Field correctness is scored separately. Read the full per-answer review.',
        'primary_round':'real-clean',
        'diagnostic_round':'real (shared calculator failed its macOS RLIMIT_AS setup; not a clean cost comparison)',
        'status':'in progress' if sum(r['stage']=='real-clean' for r in rows)<9 else 'all corrected trials recorded'}
    out=ROOT/'reports';out.mkdir(exist_ok=True)
    (out/'results.json').write_text(json.dumps(report,indent=2));(out/'answer-review.json').write_text(json.dumps(details,indent=2))
    with (out/'runs.csv').open('w') as stream:
        if rows:
            writer=csv.DictWriter(stream,fieldnames=list(rows[0]),lineterminator='\n');writer.writeheader();writer.writerows(rows)
    lines=['# Doom comparison','',f"Model: gpt-6.1-sol; effort: high. {report['status']}.",'',
        '**Primary comparison: real-clean.** The original real round is diagnostic because the shared calculator failed its macOS memory-limit setup. All original results remain below. Tiny timings include REA lazy analysis; real-round timings prewarm all engines.','',
        '| Round | Tool | Runs | Correct fields | Complete questions | Median agent time | Tokens incl. cached | API equivalent* |',
        '|---|---|---:|---:|---:|---:|---:|---:|']
    for g in groups:
        time_label=f"{g['median_agent_seconds']:.1f}s" if g['median_agent_seconds'] is not None else 'unavailable'
        token_label=f"{g['total_tokens']:,}"+(' + unavailable' if g['runs_with_unavailable_usage'] else '')
        lines.append(f"| {g['stage']} | {g['arm']} | {g['runs']} | {g['correct']}/{g['fields']} | {g['questions_passed']}/{g['questions']} | {time_label} | {token_label} | ${g['usd_standard_short_equivalent']:.3f} |")
    lines+=['','*Standard short-context API-equivalent estimate, not a subscription charge. Cached input is discounted. Missing usage is not zero. See pricing.json for long-context sensitivity and tier assumptions.','',
        'Backend setup is measured separately. Ours and community use copies of the same analyzed Ghidra project; stock REA opens the same stripped executable. All processes and model sessions are fresh.','',
        'One binary, six related questions, three repetitions per tool. No general superiority claim. The tiny question is repeated in the real round.','',
        'Proof: [results.json](results.json), [runs.csv](runs.csv), [per-answer review](answer-review.json), [tiny protocol](../benchmark/protocol.json), [diagnostic protocol](../benchmark/protocol-real.json), [primary protocol](../benchmark/protocol-real-clean.json).']
    (out/'results.md').write_text('\n'.join(lines)+'\n')
    body='<h1>Doom comparison</h1><p>gpt-6.1-sol · high effort · '+html.escape(report['status'])+'</p>'
    body+='<p><strong>Primary comparison: real-clean.</strong> Original real trials are diagnostic: the shared calculator failed its macOS resource-limit setup. Those trials are retained below. Tiny REA time includes lazy analysis; real rounds prewarm all engines.</p><p>Exact integer scoring against a private mutation key. API estimates are not subscription charges. One binary and three repeats per tool do not establish general superiority.</p>'
    body+='<table><thead><tr>'+''.join('<th>'+x+'</th>' for x in ['Round','Tool','Runs','Fields correct','Questions passed','Median agent time','Total tokens','API estimate*'])+'</tr></thead><tbody>'
    for g in groups:
        cells=[g['stage'],g['arm'],g['runs'],f"{g['correct']}/{g['fields']}",f"{g['questions_passed']}/{g['questions']}",f"{g['median_agent_seconds']:.1f}s" if g['median_agent_seconds'] is not None else 'N/A',f"{g['total_tokens']:,}",f"${g['usd_standard_short_equivalent']:.3f}"]
        body+='<tr>'+''.join('<td>'+html.escape(str(x))+'</td>' for x in cells)+'</tr>'
    body+='</tbody></table><p>*Standard short-context API equivalent; cached input discounted. See JSON for missing usage and long-context sensitivity.</p>'
    body+='<p><a href="results.json">All metrics</a> · <a href="answer-review.json">Every answer and evidence check</a> · <a href="runs.csv">CSV</a> · <a href="../benchmark/protocol.json">Tiny protocol</a> · <a href="../benchmark/protocol-real.json">Diagnostic protocol</a> · <a href="../benchmark/protocol-real-clean.json">Primary protocol</a></p>'
    for detail in details:
        row=detail['run'];body+='<details><summary>'+html.escape(f"{row['run_id']} · {row['arm']} · {row['correct']}/{row['fields']}")+'</summary><pre>'+html.escape(json.dumps(detail,indent=2))+'</pre></details>'
    page='<!doctype html><meta charset="utf-8"><title>Every App Is Open Source — private Doom results</title><style>body{max-width:1100px;margin:45px auto;padding:0 24px;font:16px/1.6 system-ui;color:#17212b;background:#fafafa}table{border-collapse:collapse;width:100%;font-size:14px}th,td{padding:10px;border-bottom:1px solid #ccd2d8;text-align:left}th{background:#e8edf1}a{color:#124e92}details{margin:16px 0;padding:12px;background:white;border:1px solid #d5dbe0}summary{cursor:pointer;font-weight:600}pre{white-space:pre-wrap;overflow-wrap:anywhere;font-size:12px}</style>'+body
    (out/'results.html').write_text(page)
    print(json.dumps({'status':report['status'],'groups':groups},indent=2))
    return report


if __name__=='__main__':summarize()
