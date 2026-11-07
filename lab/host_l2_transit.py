"""Permit lab-only, same-bridge transit before Docker's internal-subnet filter.

Keeps internal/isolated networks, NAT disabled, and host firewall policy intact.
Changes only the project-owned SCP_Gxx_L2 chain and its DOCKER-USER jump.
Windows: Docker Desktop WSL backend; Linux: run with host root privileges.
"""
import argparse
import json
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    action=parser.add_mutually_exclusive_group(required=True)
    action.add_argument('--apply',action='store_true')
    action.add_argument('--remove',action='store_true')
    action.add_argument('--show',action='store_true',help='Read current project rules without changing them')
    args=parser.parse_args()
    cfg=json.loads((ROOT/'project.json').read_text(encoding='utf-8'))
    gid=cfg['group_id']
    if not re.fullmatch(r'[0-9]{2}',gid or ''): raise SystemExit('Confirmed two-digit group required')
    g=int(gid); project=f'scp-g{gid}-m1'; chain=f'SCP_G{gid}_L2'; tag=project+'-l2-transit'
    cli=shutil.which('docker')
    if not cli:
        cli=str(Path(os.environ.get('LOCALAPPDATA',''))/'Programs/DockerDesktop/resources/bin/docker.exe')

    def run(argv,allow_failure=False):
        r=subprocess.run(argv,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=20)
        if r.returncode and not allow_failure:
            raise RuntimeError(f'Command failed: {argv}: {r.stderr.strip()}')
        return r

    if os.name=='nt':
        base=['wsl.exe','-d','docker-desktop','-u','root','--']
        pids=run(base+['pidof','dockerd']).stdout.split()
        if len(pids)!=1 or not pids[0].isdigit(): raise SystemExit('Expected one Docker daemon in docker-desktop WSL')
        host=base+['nsenter','-t',pids[0],'-n','-m','--']
    else:
        if os.geteuid()!=0: raise SystemExit('Run on the Docker host with sudo/root')
        host=[]
    def ipt(*argv,allow_failure=False): return run(host+['iptables','-w','5',*argv],allow_failure)

    # Never flush Docker's chains or change a global/default policy.
    ipt('-S','DOCKER-USER')
    existing=ipt('-S',chain,allow_failure=True)
    if existing.returncode==0:
        for line in existing.stdout.splitlines():
            if line.startswith('-A ') and tag not in line:
                raise SystemExit('Existing chain contains unrecognized rules; preserved without modification')
    jump=['-m','comment','--comment',tag,'-j',chain]
    if args.show:
        if existing.returncode!=0: raise SystemExit('Project L2 transit chain is absent')
        print(existing.stdout.strip()); return
    if args.remove:
        if ipt('-C','DOCKER-USER',*jump,allow_failure=True).returncode==0:
            ipt('-D','DOCKER-USER',*jump)
        if existing.returncode==0:
            ipt('-F',chain); ipt('-X',chain)
        print('Removed project-owned L2 transit rules only.'); return

    ids=run([cli,'network','ls','-q','--filter',f'label=com.docker.compose.project={project}']).stdout.split()
    if len(ids)!=3: raise SystemExit('Exactly three running project networks required')
    nets=json.loads(run([cli,'network','inspect',*ids]).stdout)
    if {n['Name'] for n in nets}!={project+'_'+n for n in ('wan','hq','branch')}:
        raise SystemExit('Unexpected network names; preserved without changes')
    bridges=[]
    for n in nets:
        if n['Driver']!='bridge' or not n['Internal'] or n['Options'].get('com.docker.network.bridge.enable_ip_masquerade')!='false' or n['Options'].get('com.docker.network.bridge.gateway_mode_ipv4')!='isolated':
            raise SystemExit('Requires internal, isolated, non-masqueraded project bridges')
        br=n['Options'].get('com.docker.network.bridge.name','br-'+n['Id'][:12])
        if not re.fullmatch(r'br-[0-9a-f]{12}',br): raise SystemExit('Unexpected bridge name; no changes')
        run(host+['test','-d',f'/sys/class/net/{br}/bridge'])
        bridges.append(br)
    if existing.returncode!=0: ipt('-N',chain)
    else: ipt('-F',chain)
    pairs=[(f'10.{g}.0.0/16',f'10.{g}.0.0/16'),
           (f'172.16.{g}.66/32',f'10.{g}.2.0/24'),
           (f'10.{g}.2.0/24',f'172.16.{g}.66/32')]
    rules=[]
    for br in bridges:
        for src,dst in pairs:
            rule=['-i',br,'-o',br,'-s',src,'-d',dst,'-m','comment','--comment',tag,'-j','ACCEPT']
            ipt('-A',chain,*rule); rules.append(rule)
    ipt('-A',chain,'-m','comment','--comment',tag,'-j','RETURN')
    if ipt('-C','DOCKER-USER',*jump,allow_failure=True).returncode!=0:
        ipt('-I','DOCKER-USER','1',*jump)
    current=ipt('-S',chain).stdout
    record={'utc':datetime.now(timezone.utc).isoformat(),'project':project,'chain':chain,'bridges':bridges,
       'scope':'Same input/output project bridge and lab source/destination only; no external interface, NAT, global sysctl or default policy changed.',
       'rules':current.splitlines(),'reason':'Docker DOCKER-INTERNAL drops routed lab destinations on an internal bridge before they reach the gateway container.'}
    path=ROOT/'evidence/sanitized_logs/M1_host_l2_rules.json'
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(record,indent=2)+'\n',encoding='utf-8')
    print(f'Installed {len(rules)} scoped rules on {len(bridges)} project bridges; internal isolation retained.')

if __name__=='__main__': main()
