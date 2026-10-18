from pathlib import Path
import json
import subprocess
import run

reports=[]
for arm in ['ours','community','rea']:
    directory,engine,log=run.prepare(arm,'calibration/p-'+arm,run.ROOT/'private/fixture')
    try:
        subprocess.run(['node',str(run.BENCH/'probe.mjs'),arm,str(directory)],check=True,timeout=180)
        reports.append(json.loads((directory/'probe.json').read_text()))
    finally:run.cleanup(engine,log)
(run.BENCH/'preflight.json').write_text(json.dumps(reports,indent=2))
