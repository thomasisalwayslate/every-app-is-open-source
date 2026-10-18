"""Build a complete private mutated Chocolate Doom using existing Apple clang.

No CMake/autotools/pkg-config installation. Source lists come from upstream CMake.
Actual random mutations, patch, symbols and key are written ONLY under private/.
"""
from pathlib import Path
import concurrent.futures
import hashlib
import json
import os
import re
import secrets
import shutil
import subprocess

ROOT=Path(__file__).resolve().parents[1]


def source_list(path, variable):
    text=path.read_text()
    block=re.search(r'(?:set\('+re.escape(variable)+r'\s+|add_library\('+re.escape(variable)+r'\s+STATIC\s+)(.*?)\)',text,re.S)
    if not block:raise ValueError(f'Missing source list {variable}')
    return re.findall(r'\b[\w/]+\.c\b',block.group(1))


def main(root=ROOT):
    private = root / 'private/doom'
    upstream_root = root / 'private/upstream'
    candidates = list(upstream_root.iterdir()) if upstream_root.is_dir() else []
    if len(candidates) != 1 or not (candidates[0] / 'src/doom/p_pspr.c').is_file():
        raise RuntimeError('Prepare public source first: python3 benchmark/prepare.py')
    if not (root / 'private/download.json').is_file():
        raise RuntimeError('Missing upstream receipt; run benchmark/prepare.py in a fresh checkout')
    for path in ['/opt/homebrew/include/SDL2/SDL.h', '/opt/homebrew/include/SDL2/SDL_mixer.h', '/opt/homebrew/include/SDL2/SDL_net.h']:
        if not Path(path).is_file():
            raise RuntimeError('Benchmark build needs the documented SDL2 Homebrew packages; see docs/BENCHMARK.md')
    target = root / 'benchmark/targets/chocolate-doom-secret'
    if target.exists():
        raise RuntimeError('Target already exists; preserve it and use a fresh benchmark directory')
    private.mkdir(parents=True, exist_ok=False)
    upstream = candidates[0]
    source=private/'source';shutil.copytree(upstream,source)
    rng=secrets.SystemRandom()
    values={'gunshot_base':rng.choice([7,9,11,13]),'shotgun_pellets':rng.choice([9,11,13]),
            'imp_health':rng.randrange(83,132),'imp_speed':rng.choice([9,11,13]),
            'baron_health':rng.randrange(1201,1600),'baron_speed':rng.choice([10,12,14]),
            'rocket_speed':rng.choice([23,27,31]),'demon_damage_base':rng.choice([6,7,9])}
    pspr=source/'src/doom/p_pspr.c';text=pspr.read_text()
    gunshot=re.search(r'\nP_GunShot\s*\n.*?\n}',text,re.S)
    assert gunshot and gunshot[0].count('damage = 5*(P_Random ()%3+1);')==1
    text=text[:gunshot.start()]+gunshot[0].replace('damage = 5*(P_Random ()%3+1);',f"damage = {values['gunshot_base']}*(P_Random ()%3+1);")+text[gunshot.end():]
    assert text.count('for (i=0 ; i<7 ; i++)')==1
    text=text.replace('for (i=0 ; i<7 ; i++)',f"for (i=0 ; i<{values['shotgun_pellets']} ; i++)");pspr.write_text(text)
    enemy=source/'src/doom/p_enemy.c';text=enemy.read_text()
    assert text.count('damage = ((P_Random()%10)+1)*4;')==1
    text=text.replace('damage = ((P_Random()%10)+1)*4;',f"damage = ((P_Random()%10)+1)*{values['demon_damage_base']};");enemy.write_text(text)
    info=source/'src/doom/info.c';text=info.read_text()
    for kind,replacements in [('MT_TROOP',{'spawnhealth':str(values['imp_health']),'speed':str(values['imp_speed'])}),
        ('MT_BRUISER',{'spawnhealth':str(values['baron_health']),'speed':str(values['baron_speed'])}),
        ('MT_ROCKET',{'speed':str(values['rocket_speed'])+'*FRACUNIT'})]:
        pat=r'(\{\s*// '+kind+r'\n)(.*?)(\n    },)'
        match=re.search(pat,text,re.S);assert match,kind
        block=match.group(2)
        for field,value in replacements.items():
            block,n=re.subn(r'(?m)^(\s*)[^,\n]+,(\s*// '+field+r'\s*)$',lambda m:m[1]+value+','+m[2],block)
            assert n==1,(kind,field,n)
        text=text[:match.start(2)]+block+text[match.end(2):]
    info.write_text(text)
    patch=subprocess.run(['diff','-ru',str(upstream),str(source)],capture_output=True,text=True)
    (private/'mutations.patch').write_text(patch.stdout)
    (private/'values.json').write_text(json.dumps(values,indent=2))
    build=private/'build';build.mkdir()
    config='''#define PACKAGE_NAME "Chocolate Doom"
#define PACKAGE_TARNAME "chocolate-doom"
#define PACKAGE_VERSION "3.1.1"
#define PACKAGE_STRING "Chocolate Doom 3.1.1"
#define PROGRAM_PREFIX "chocolate-"
#define HAVE_DIRENT_H 1
#define HAVE_DECL_STRCASECMP 1
#define HAVE_DECL_STRNCASECMP 1
'''
    (build/'config.h').write_text(config)
    paths=[]
    for variable in ['COMMON_SOURCE_FILES','GAME_SOURCE_FILES','DEHACKED_SOURCE_FILES']:
        paths += [source/'src'/p for p in source_list(source/'src/CMakeLists.txt',variable)]
    paths += [source/'src/doom'/p for p in source_list(source/'src/doom/CMakeLists.txt','doom')]
    for lib in ['opl','pcsound','textscreen']:
        paths += [source/lib/p for p in source_list(source/lib/'CMakeLists.txt',lib)]
    paths=list(dict.fromkeys(paths))
    include=[build,source/'src',source/'src/doom',source/'opl',source/'pcsound',source/'textscreen',Path('/opt/homebrew/include/SDL2')]
    flags=['clang','-std=c99','-O2','-g','-fno-omit-frame-pointer','-Wno-deprecated-declarations','-Wno-incompatible-pointer-types','-D_THREAD_SAFE']
    flags += [arg for directory in include for arg in ['-I',str(directory)]]
    commands=[]
    def compile(path):
        obj=build/(str(path.relative_to(source)).replace('/','_')+'.o')
        cmd=flags+['-c',str(path),'-o',str(obj)];commands.append(cmd)
        process=subprocess.run(cmd,capture_output=True,text=True)
        if process.returncode:
            (build/(obj.name+'.error.log')).write_text(process.stdout+process.stderr)
            raise RuntimeError(f'Compile failed: {path.name}; see {obj.name}.error.log')
        return obj
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:objects=list(pool.map(compile,paths))
    raw=private/'chocolate-doom-unstripped'
    link=['clang',*[str(p) for p in objects],'-L/opt/homebrew/lib','-lSDL2','-lSDL2_mixer','-lSDL2_net','-lm','-framework','Cocoa','-Wl,-map,'+str(private/'link.map'),'-o',str(raw)]
    process=subprocess.run(link,capture_output=True,text=True)
    (private/'link.log').write_text(process.stdout+process.stderr)
    if process.returncode:raise RuntimeError('Link failed; see private/doom/link.log')
    subprocess.run(['dsymutil',str(raw),'-o',str(private/'chocolate-doom.dSYM')],check=True)
    symbols=subprocess.check_output(['nm','-n',str(raw)],text=True);(private/'symbols.txt').write_text(symbols)
    targetdir=root/'benchmark/targets';targetdir.mkdir(parents=True, exist_ok=True)
    target=targetdir/'chocolate-doom-secret'
    subprocess.run(['strip','-o',str(target),str(raw)],check=True)
    subprocess.run(['codesign','--force','--sign','-',str(target)],capture_output=True,check=True)
    stripped_symbols=subprocess.check_output(['nm','-a',str(target)],text=True,stderr=subprocess.STDOUT)
    for name in ['_P_GunShot','_A_FireShotgun','_A_SargAttack','_mobjinfo']:
        assert name in symbols and name not in stripped_symbols,name
    version=subprocess.run([str(target),'--version'],capture_output=True,text=True,timeout=10)
    (private/'version.json').write_text(json.dumps({'exit_code':version.returncode,'stdout':version.stdout,'stderr':version.stderr},indent=2))
    if version.returncode:raise RuntimeError('Stripped executable failed its version smoke test')
    fields={**values,'gunshot_min':values['gunshot_base'],'gunshot_max':values['gunshot_base']*3,
        'shotgun_min':values['shotgun_pellets']*values['gunshot_base'],
        'shotgun_max':values['shotgun_pellets']*values['gunshot_base']*3,
        'demon_min':values['demon_damage_base'],'demon_max':values['demon_damage_base']*10}
    (private/'answer-key.json').write_text(json.dumps(fields,indent=2))
    # Link an oracle against the exact game objects, replacing only the entry point.
    oracle=private/'table-oracle.c'
    oracle.write_text('#include <stdio.h>\n#include "info.h"\nint main(void){printf("{\\"imp_health\\":%d,\\"imp_speed\\":%d,\\"baron_health\\":%d,\\"baron_speed\\":%d,\\"rocket_speed\\":%d}\\n",mobjinfo[MT_TROOP].spawnhealth,mobjinfo[MT_TROOP].speed,mobjinfo[MT_BRUISER].spawnhealth,mobjinfo[MT_BRUISER].speed,mobjinfo[MT_ROCKET].speed/65536);return 0;}\n')
    oraclemain=build/'oracle.o';subprocess.run(flags+['-c',str(oracle),'-o',str(oraclemain)],check=True)
    oraclebin=private/'table-oracle'
    cmd=['clang',str(oraclemain),*[str(p) for p in objects if p.name!='src_i_main.c.o'],'-L/opt/homebrew/lib','-lSDL2','-lSDL2_mixer','-lSDL2_net','-lm','-framework','Cocoa','-o',str(oraclebin)]
    process=subprocess.run(cmd,capture_output=True,text=True);(private/'oracle-link.log').write_text(process.stdout+process.stderr)
    if process.returncode:raise RuntimeError('Runtime oracle link failed')
    observed=json.loads(subprocess.check_output([str(oraclebin)],text=True))
    assert all(observed[k]==values[k] for k in observed)
    (private/'runtime-table-oracle.json').write_text(json.dumps(observed,indent=2))
    manifest={'upstream':json.loads((root/'private/download.json').read_text()),'version':'3.1.1',
        'target':str(target),'sha256':hashlib.sha256(target.read_bytes()).hexdigest(),'bytes':target.stat().st_size,
        'mutation_count':8,'source_files':len(paths),'stripped':True,'runtime_table_oracle':True,
        'compiler':subprocess.check_output(['clang','--version'],text=True).splitlines()[0],
        'note':'Full game executable; stock production strings/imports retained, internal/debug labels stripped. No WAD or gameplay test. Weapon oracle from frozen mutated source; table fields additionally executed from exact linked objects.'}
    (private/'build-commands.json').write_text(json.dumps(commands+[link],indent=2))
    (private/'target-manifest.json').write_text(json.dumps(manifest,indent=2))
    print(json.dumps(manifest,indent=2),flush=True)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=ROOT)
    args = parser.parse_args()
    main(args.root.resolve())
