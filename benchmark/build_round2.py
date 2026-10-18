"""Private control-flow mutant; build and executable oracle, never exposed to agents."""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import secrets
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]
OLD=ROOT/'private/doom'; D=ROOT/'private/round2'

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def invoke(c):
    p=subprocess.run(c,capture_output=True,text=True)
    if p.returncode:raise RuntimeError(p.stderr[-6000:])

def build(resume=False):
    if resume:
        values=json.loads((D/'values.json').read_text())
    else:
        D.mkdir(exist_ok=False)
        shutil.copytree(OLD/'source',D/'source')
    values=values if resume else {k:secrets.choice(v) for k,v in {
        'green_divisor':[4,5], 'invul_threshold':[911,977],
        'fallback_shell_threshold':[3,4], 'fallback_cell_threshold':[44,47,49],
        'ammo_skill_multiplier':[3,4], 'splash_distance_divisor':[2,3],
        'bfg_rays':[37,43], 'bfg_rolls':[11,13,17]}.items()}
    patches={
        'p_inter.c': [('saved = damage/3;',f"saved = damage/{values['green_divisor']};"),
            ('damage < 1000',f"damage < {values['invul_threshold']}"),
            ('num <<= 1;',f"num *= {values['ammo_skill_multiplier']};")],
        'p_pspr.c': [('player->ammo[am_shell]>2',f"player->ammo[am_shell]>{values['fallback_shell_threshold']}"),
            ('player->ammo[am_cell]>40',f"player->ammo[am_cell]>{values['fallback_cell_threshold']}"),
            ('i<40',f"i<{values['bfg_rays']}"),('ANG90/40*i',f"ANG90/{values['bfg_rays']}*i"),
            ('j<15',f"j<{values['bfg_rolls']}")],
        'p_map.c': [('bombdamage - dist);',f"bombdamage - dist/{values['splash_distance_divisor']});")]}
    for filename,replacements in patches.items():
        if resume:break
        p=D/'source/src/doom'/filename; text=p.read_text()
        for before,after in replacements:
            if text.count(before)!=1:raise RuntimeError('Patch is not unique: '+before)
            text=text.replace(before,after)
        p.write_text(text)
    (D/'values.json').write_text(json.dumps(values,indent=2))
    commands=json.loads((OLD/'build-commands.json').read_text())
    commands=[[x.replace(str(OLD),str(D)) for x in c] for c in commands]
    (D/'build').mkdir(exist_ok=resume)
    shutil.copy2(OLD/'build/config.h',D/'build/config.h')
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:list(pool.map(invoke,commands[:-1]))
    invoke(commands[-1]);(D/'build-commands.json').write_text(json.dumps(commands,indent=2))
    original=Path(commands[-1][-1])
    target=ROOT/'benchmark/targets/chocolate-doom-round2'
    if target.exists():raise RuntimeError('Target already exists')
    invoke(['strip','-o',str(target),str(original)])
    invoke(['codesign','--force','--sign','-',str(target)])
    manifest={'target':str(target.relative_to(ROOT)),'sha256':sha(target),'bytes':target.stat().st_size,
        'base_sha256':sha(ROOT/'benchmark/targets/chocolate-doom-secret'),
        'source':'Chocolate Doom 3.1.1; eight additional private control-flow/arithmetic mutations',
        'defined_symbols':subprocess.check_output(['nm','-U',str(target)],text=True),
        'version_smoke':subprocess.check_output([str(target),'--version'],text=True).strip(),
        'oracle':'private/round2/runtime-oracle.json'}
    (D/'manifest.json').write_text(json.dumps(manifest,indent=2))
    print('Built private round2 binary:',manifest['sha256'],manifest['bytes'])

if __name__=='__main__':
    import sys
    build(resume='--resume' in sys.argv)
