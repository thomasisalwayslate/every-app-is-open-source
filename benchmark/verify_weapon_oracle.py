"""Execute the actual mutated gameplay functions with private I/O/random probes.

The benchmark binary is untouched. Only the oracle build substitutes random/world
boundaries so the real weapon loops and damage arithmetic can run without a WAD.
"""
from pathlib import Path
import json
import subprocess

ROOT=Path(__file__).resolve().parents[1]
D=ROOT/'private/doom';commands=json.loads((D/'build-commands.json').read_text())
compile_commands=commands[:-1];link=commands[-1]
objects=[Path(command[-1]) for command in compile_commands]
flags=compile_commands[0][:-4]
defines=['-DP_Random=EAOS_Random','-DP_SubRandom=EAOS_SubRandom',
    '-DP_LineAttack=EAOS_LineAttack','-DP_AimLineAttack=EAOS_AimLineAttack',
    '-DS_StartSound=EAOS_StartSound','-DP_SetMobjState=EAOS_SetMobjState','-DP_DamageMobj=EAOS_DamageMobj']
special=[]
for name in ['p_pspr.c','p_enemy.c']:
    obj=D/'build'/('oracle-'+name+'.o')
    command=flags+defines+['-c',str(D/'source/src/doom'/name),'-o',str(obj)]
    subprocess.run(command,check=True,capture_output=True);special.append(obj)
main=D/'weapon-oracle.c'
main.write_text('''#include <stdio.h>
#include <string.h>
#include "doomstat.h"
#include "p_local.h"
static int roll, calls, total, last;
int EAOS_Random(void) { return roll; }
int EAOS_SubRandom(void) { return 0; }
void EAOS_StartSound(void *origin, int sound_id) {}
boolean EAOS_SetMobjState(mobj_t *mo, statenum_t state) { return true; }
fixed_t EAOS_AimLineAttack(mobj_t *mo, angle_t angle, fixed_t distance) { linetarget=mo; return 0; }
void EAOS_LineAttack(mobj_t *mo, angle_t angle, fixed_t distance, fixed_t slope, int damage) { ++calls; total+=damage; last=damage; }
void EAOS_DamageMobj(mobj_t *target,mobj_t *inflictor,mobj_t *source,int damage) { ++calls; total+=damage; last=damage; }
void P_GunShot(mobj_t *, boolean);
void A_FireShotgun(player_t *,pspdef_t *);
void A_SargAttack(mobj_t *);
int main(void) {
 mobj_t actor={0},victim={0};player_t player={0};
 int gmin,gmax,pellets,smin,smax,dmin,dmax;
 actor.target=&victim; player.mo=&actor; player.readyweapon=wp_shotgun; player.ammo[am_shell]=100;
 roll=0;P_GunShot(&actor,true);gmin=last;
 roll=2;P_GunShot(&actor,true);gmax=last;
 calls=0;total=0;roll=0;A_FireShotgun(&player,&player.psprites[ps_weapon]);pellets=calls;smin=total;
 calls=0;total=0;roll=2;A_FireShotgun(&player,&player.psprites[ps_weapon]);smax=total;
 gameversion=exe_doom_1_2;
 roll=0;A_SargAttack(&actor);dmin=last;
 roll=9;A_SargAttack(&actor);dmax=last;
 printf("{\\"gunshot_base\\":%d,\\"gunshot_min\\":%d,\\"gunshot_max\\":%d,\\"shotgun_pellets\\":%d,\\"shotgun_min\\":%d,\\"shotgun_max\\":%d,\\"demon_damage_base\\":%d,\\"demon_min\\":%d,\\"demon_max\\":%d}\\n",gmin,gmin,gmax,pellets,smin,smax,dmin,dmin,dmax);
 return 0;
}
''')
main_obj=D/'build/weapon-oracle-main.o'
subprocess.run(flags+['-c',str(main),'-o',str(main_obj)],check=True,capture_output=True)
remaining=[str(p) for p in objects if p.name not in ['src_i_main.c.o','src_doom_p_pspr.c.o','src_doom_p_enemy.c.o']]
executable=D/'weapon-oracle'
command=['clang',str(main_obj),*[str(p) for p in special],*remaining,'-L/opt/homebrew/lib','-lSDL2','-lSDL2_mixer','-lSDL2_net','-lm','-framework','Cocoa','-o',str(executable)]
subprocess.run(command,check=True,capture_output=True)
result=json.loads(subprocess.check_output([str(executable)],text=True,timeout=10))
expected=json.loads((D/'answer-key.json').read_text())
assert all(expected[k]==value for k,value in result.items()),'Oracle disagrees with frozen mutation key'
(D/'runtime-weapon-oracle.json').write_text(json.dumps(result,indent=2))
manifest=json.loads((ROOT/'benchmark/target-manifest.json').read_text())
manifest['runtime_weapon_oracle']=True
manifest['note']='Full game executable; production strings/imports retained, internal/debug labels stripped. All eight changed constants and derived requested outcomes checked by executable oracles using the actual mutated game source/objects. Weapon oracle substitutes random/world I/O boundaries; no WAD/gameplay test.'
(ROOT/'benchmark/target-manifest.json').write_text(json.dumps(manifest,indent=2))
print('Runtime weapon oracle agrees with every weapon field; target executable unchanged.')
