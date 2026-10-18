"""No model calls; fixture-only preparation/isolation checks for all three arms."""
import json
import os
import subprocess
from pathlib import Path
import run

records=[]
for arm,short in [('ours','o'),('community','g'),('rea','r')]:
 directory,engine,log=run.prepare(arm,'calibration/q2'+short,run.ROOT/'private/fixture',env={**os.environ,'EAOS_STUDY_PROFILE':'round2','EAOS_WARMUP_ADDRESS':'100000460'})
 try:
  subprocess.run(['node',str(run.BENCH/'probe.mjs'),arm,str(directory)],check=True,timeout=180)
  probe=json.loads((directory/'probe.json').read_text());warm=json.loads((directory/'decompiler-warmup.json').read_text())
  assert not warm['result'].get('isError')
  assert 'return' in json.dumps(warm['result'])
  assert probe['tools']=={'ours':7,'community':29,'rea':209}[arm]
  results=probe['results']
  assert not results[0].get('error') and not results[0]['result'].get('isError')
  assert not results[1].get('error') and not results[1]['result'].get('isError')
  if arm=='ours':assert results[-1]['result']['isError']
  if arm=='rea':assert results[-1].get('error') or results[-1]['result'].get('isError')
  records.append({'arm':arm,'tools':probe['tools'],'prewarmed':True,'search_decompile_ok':True,'isolation_probe_ok':True,'setup':json.loads((directory/'ready.json').read_text())})
 finally:run.cleanup(engine,log)
(run.ROOT/'reports/round2/engine-checks.json').write_text(json.dumps(records,indent=2))
print('All stock engine catalogs, prewarming, search/decompile and isolation probes passed.')
