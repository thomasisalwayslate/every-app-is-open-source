"""Execute real round-2 gameplay units with explicit world-I/O boundaries."""
from pathlib import Path
import json
import subprocess
from build_round2 import ROOT,D,invoke,sha

C=r'''
#include <stdio.h>
#include <string.h>
#include "doomstat.h"
#include "p_local.h"
#include "info.h"
static int roll, damage_calls, total_damage, ray_calls;
static mobj_t victim;
int ProbeRandom(void) { return roll; }
fixed_t ProbeAim(mobj_t *mo,angle_t an,fixed_t distance) { ++ray_calls; linetarget=&victim; return 0; }
mobj_t *ProbeSpawn(fixed_t x,fixed_t y,fixed_t z,mobjtype_t type) { return &victim; }
void ProbeDamage(mobj_t *target,mobj_t *inflictor,mobj_t *source,int damage) { ++damage_calls;total_damage+=damage; }
boolean ProbeSight(mobj_t *a,mobj_t *b) { return true; }
void A_BFGSpray(mobj_t *);
boolean P_CheckAmmo(player_t *);
boolean P_GiveAmmo(player_t *,ammotype_t,int);
boolean PIT_RadiusAttack(mobj_t *);
extern mobj_t *bombspot,*bombsource;
extern int bombdamage;
static player_t player;
static mobj_t actor;
static mobjinfo_t info;
static sector_t sector;
static subsector_t subsector;
void reset_player(void) {
 memset(&player,0,sizeof player);memset(&actor,0,sizeof actor);memset(&info,0,sizeof info);
 memset(&sector,0,sizeof sector);memset(&subsector,0,sizeof subsector);
 subsector.sector=&sector;actor.subsector=&subsector;actor.info=&info;
 actor.player=&player;actor.flags=MF_SHOOTABLE;actor.health=100;
 player.mo=&actor;player.health=100;player.pendingweapon=wp_nochange;
 gameskill=sk_medium;gamemode=commercial;gameversion=exe_doom_1_9;roll=255;
}
int splash(int type,int x,int y,int radius) {
 mobj_t spot={0},thing={0};thing.type=type;thing.flags=MF_SHOOTABLE;
 thing.x=x*FRACUNIT;thing.y=y*FRACUNIT;thing.radius=radius*FRACUNIT;
 bombspot=&spot;bombsource=0;bombdamage=128;total_damage=damage_calls=0;
 PIT_RadiusAttack(&thing);return total_damage;
}
int main(void) {
 reset_player();gameskill=sk_baby;player.armortype=1;player.armorpoints=17;
 P_DamageMobj(&actor,0,0,101);int green_health=player.health,green_armor=player.armorpoints;
 reset_player();gameskill=sk_baby;player.armortype=2;player.armorpoints=9;
 P_DamageMobj(&actor,0,0,101);int blue_health=player.health,blue_armor=player.armorpoints,blue_type=player.armortype;
 int max_blocked=-1;
 for(int d=0;d<1100;++d) {
  reset_player();player.health=actor.health=5000;player.powers[pw_invulnerability]=1;
  P_DamageMobj(&actor,0,0,d);if(player.health==5000)max_blocked=d;
 }
 reset_player();player.health=actor.health=5000;gameskill=sk_baby;player.powers[pw_invulnerability]=1;
 P_DamageMobj(&actor,0,0,1900);int baby_invul_health=player.health;
 reset_player();player.health=actor.health=37;sector.special=11;player.powers[pw_invulnerability]=1;
 P_DamageMobj(&actor,0,0,10000);int exit_health=player.health;
 reset_player();player.readyweapon=wp_supershotgun;player.ammo[am_shell]=2;
 int ssg_fire_two=P_CheckAmmo(&player),ssg_min=-1,bfg_min=-1,bfg_fire_min=-1;
 for(int shells=0;shells<12;++shells) {
  reset_player();player.readyweapon=wp_missile;weaponinfo[wp_missile].downstate=S_NULL;
  player.weaponowned[wp_supershotgun]=player.weaponowned[wp_shotgun]=1;player.ammo[am_shell]=shells;
  P_CheckAmmo(&player);if(ssg_min<0&&player.pendingweapon==wp_supershotgun)ssg_min=shells;
 }
 for(int cells=0;cells<70;++cells) {
  reset_player();player.readyweapon=wp_missile;weaponinfo[wp_missile].downstate=S_NULL;
  player.weaponowned[wp_bfg]=1;player.ammo[am_cell]=cells;
  P_CheckAmmo(&player);if(bfg_min<0&&player.pendingweapon==wp_bfg)bfg_min=cells;
  reset_player();player.readyweapon=wp_bfg;weaponinfo[wp_bfg].downstate=S_NULL;
  player.ammo[am_cell]=cells;if(P_CheckAmmo(&player)&&bfg_fire_min<0)bfg_fire_min=cells;
 }
 int splash_diagonal=splash(MT_TROOP,70,90,20),splash_inner=splash(MT_TROOP,147,0,20);
 int splash_edge=splash(MT_TROOP,148,0,20),splash_cyber=splash(MT_CYBORG,70,90,20);
 mobj_t projectile={0},shooter={0};projectile.target=&shooter;
 roll=0;damage_calls=total_damage=ray_calls=0;A_BFGSpray(&projectile);
 int bfg_rays=ray_calls,bfg_min_ray=total_damage/damage_calls;
 roll=7;damage_calls=total_damage=ray_calls=0;A_BFGSpray(&projectile);
 int bfg_max_ray=total_damage/damage_calls,bfg_total_max=total_damage;
 reset_player();gameskill=sk_baby;player.readyweapon=wp_fist;player.maxammo[am_shell]=50;
 player.weaponowned[wp_shotgun]=player.weaponowned[wp_supershotgun]=1;
 P_GiveAmmo(&player,am_shell,0);int ammo_gain=player.ammo[am_shell],ammo_weapon=player.pendingweapon;
 player.ammo[am_shell]=49;P_GiveAmmo(&player,am_shell,0);int ammo_cap=player.ammo[am_shell];
 int full_result=P_GiveAmmo(&player,am_shell,0);
 printf("{\"green_health\":%d,\"green_armor\":%d,\"blue_health\":%d,\"blue_armor\":%d,\"blue_type\":%d,"
 "\"invul_max_blocked\":%d,\"baby_invul_health\":%d,\"exit_health\":%d,"
 "\"ssg_fire_two\":%d,\"ssg_fallback_min\":%d,\"bfg_fallback_min\":%d,\"bfg_fire_min\":%d,"
 "\"splash_diagonal\":%d,\"splash_inner\":%d,\"splash_edge\":%d,\"splash_cyber\":%d,"
 "\"bfg_rays\":%d,\"bfg_min_ray\":%d,\"bfg_max_ray\":%d,\"bfg_total_max\":%d,"
 "\"ammo_gain\":%d,\"ammo_weapon\":%d,\"ammo_cap\":%d,\"ammo_full_result\":%d}\n",
 green_health,green_armor,blue_health,blue_armor,blue_type,max_blocked,baby_invul_health,exit_health,
 ssg_fire_two,ssg_min,bfg_min,bfg_fire_min,splash_diagonal,splash_inner,splash_edge,splash_cyber,
 bfg_rays,bfg_min_ray,bfg_max_ray,bfg_total_max,ammo_gain,ammo_weapon,ammo_cap,full_result);
}
'''

def oracle():
 commands=json.loads((D/'build-commands.json').read_text());flags=commands[0][:-4]
 probes={'p_inter.c':['-DP_Random=ProbeRandom'],
  'p_pspr.c':['-DP_Random=ProbeRandom','-DP_DamageMobj=ProbeDamage','-DP_AimLineAttack=ProbeAim','-DP_SpawnMobj=ProbeSpawn'],
  'p_map.c':['-DP_DamageMobj=ProbeDamage','-DP_CheckSight=ProbeSight']}
 special=[]
 for name,defines in probes.items():
  obj=D/'build'/('probe-'+name+'.o');invoke(flags+defines+['-c',str(D/'source/src/doom'/name),'-o',str(obj)]);special.append(str(obj))
 main=D/'oracle.c';main.write_text(C);obj=D/'build/probe-main.o';invoke(flags+['-c',str(main),'-o',str(obj)])
 exclude={'src_i_main.c.o',*[f'src_doom_{f}.o' for f in probes]}
 remaining=[c[-1] for c in commands[:-1] if Path(c[-1]).name not in exclude]
 executable=D/'oracle';invoke(['clang',str(obj),*special,*remaining,'-L/opt/homebrew/lib','-lSDL2','-lSDL2_mixer','-lSDL2_net','-lm','-framework','Cocoa','-o',str(executable)])
 result=json.loads(subprocess.check_output([str(executable)],text=True,timeout=15))
 v=json.loads((D/'values.json').read_text());div=v['green_divisor'];th=v['invul_threshold'];n=v['bfg_rolls'];r=v['bfg_rays'];distdiv=v['splash_distance_divisor']
 expected={'green_health':50+50//div,'green_armor':17-50//div,'blue_health':59,'blue_armor':0,'blue_type':0,
  'invul_max_blocked':th-1,'baby_invul_health':5000 if 950<th else 4050,'exit_health':37,
  'ssg_fire_two':1,'ssg_fallback_min':v['fallback_shell_threshold']+1,'bfg_fallback_min':v['fallback_cell_threshold']+1,'bfg_fire_min':40,
  'splash_diagonal':128-70//distdiv,'splash_inner':128-127//distdiv,'splash_edge':0,'splash_cyber':0,
  'bfg_rays':r,'bfg_min_ray':n,'bfg_max_ray':n*8,'bfg_total_max':r*n*8,
  'ammo_gain':2*v['ammo_skill_multiplier'],'ammo_weapon':2,'ammo_cap':50,'ammo_full_result':0}
 if result!=expected:raise RuntimeError('Executed gameplay and independently calculated key disagree: '+str(result))
 (D/'runtime-oracle.json').write_text(json.dumps(result,indent=2));(D/'answer-key.json').write_text(json.dumps(expected,indent=2))
 (D/'oracle-receipt.json').write_text(json.dumps({'target_sha256':sha(ROOT/'benchmark/targets/chocolate-doom-round2'),
   'oracle_sha256':sha(executable),'source_sha256':sha(main),'verified_fields':len(result),
   'boundaries':'Only random, BFG aim/spawn/damage reporting, radius sight/damage reporting mocked. Damage and ammo functions execute their real code. Weapon overlay downstate is S_NULL in fallback probes. No WAD/gameplay execution.',
   'source_files':{str(p.relative_to(D)):sha(p) for p in sorted((D/'source').rglob('*')) if p.is_file()}},indent=2))
 print('All',len(result),'fields agree between executable gameplay probes and independent arithmetic.')
if __name__=='__main__':oracle()
