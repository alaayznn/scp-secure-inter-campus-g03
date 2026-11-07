"""Validate the running M1 lab and optionally take a real gw-hq WAN capture.

No image build, PKI, TLS deployment, VPN or attack implementation is performed.
Existing PCAPs are never overwritten. Run after docker compose up is healthy.
"""
import argparse
import hashlib
import json
import os
import shutil
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
LOGS=ROOT/'evidence/sanitized_logs'
PCAP=ROOT/'evidence/pcaps/M1_baseline_wan.pcap'

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--capture',action='store_true',help='Take a real capture; refuses to overwrite existing evidence')
    parser.add_argument('--requested-by',required=True,help='Actual requester name/ID; not a claim of independent member testing')
    args=parser.parse_args()
    cfg=json.loads((ROOT/'project.json').read_text(encoding='utf-8'))
    gid=cfg['group_id']; g=int(gid); project=f'scp-g{gid}-m1'
    cli=shutil.which('docker')
    if not cli:
        candidate=Path(os.environ.get('LOCALAPPDATA',''))/'Programs/DockerDesktop/resources/bin/docker.exe'
        if candidate.is_file(): cli=str(candidate)
    if not cli: raise SystemExit('Docker CLI not found')
    prefix=[cli,'compose','-p',project,'--project-directory',str(ROOT/'lab'),'-f',str(ROOT/'lab/docker-compose.yml'),'--env-file',str(ROOT/'lab/.env')]
    LOGS.mkdir(parents=True,exist_ok=True)
    report={'utc_start':datetime.now(timezone.utc).isoformat(),'requested_by':args.requested_by,
            'execution':'Project scripted runner; independent member review/retest is not claimed',
            'group_id':gid,'capture_requested':args.capture,'checks':[],'commands':[]}
    capture=None; transcript=None

    def command(argv,expected=0,timeout=30):
        result=subprocess.run(argv,cwd=ROOT/'lab',capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=timeout)
        # Store portable executable names instead of machine-specific installation paths.
        display=['docker' if a==cli else 'python' if a==sys.executable else a.replace(str(ROOT),'PROJECT_ROOT') for a in argv]
        report['commands'].append({'utc':datetime.now(timezone.utc).isoformat(),'argv':display,
             'exit_code':result.returncode,'stdout':result.stdout.strip(),'stderr':result.stderr.strip()})
        if expected is not None and result.returncode!=expected:
            raise RuntimeError(f'Command failed ({result.returncode}): {display}: {result.stderr.strip()}')
        return result

    def dc(*argv,**kw): return command(prefix+list(argv),**kw)
    def node(role,*argv,**kw): return dc('exec','-T',role,*argv,**kw)
    def require(name,condition,expected,actual):
        report['checks'].append({'id':name,'expected':expected,'actual':actual,'result':'PASS' if condition else 'FAIL'})
        if not condition: raise RuntimeError(name+' failed')

    try:
        if args.capture and PCAP.exists(): raise RuntimeError('Existing PCAP preserved; use validation without --capture')
        resolved=json.loads(dc('config','--format','json').stdout)
        require('M1-GROUP',resolved['name']==project and resolved['services']['gw-hq']['environment']['GROUP_ID']==gid,'Confirmed group and project',resolved['name'])
        ids=dc('ps','-q').stdout.split()
        require('M1-SIX',len(ids)==6,'Exactly six current project containers',len(ids))
        states=json.loads(command([cli,'inspect',*ids]).stdout)
        roles={s['Config']['Labels']['com.docker.compose.service']:s for s in states}
        expected_roles={'gw-hq','gw-branch','web-hq','kdc','client-br','attacker'}
        require('M1-HEALTH',set(roles)==expected_roles and all(s['State']['Status']=='running' and s['State'].get('Health',{}).get('Status')=='healthy' for s in states),
                'All six required roles running/healthy',{r:s['State'].get('Health',{}).get('Status') for r,s in roles.items()})
        require('M1-EXPOSURE',all(not s['HostConfig']['Privileged'] and not s['HostConfig']['PortBindings'] and s['HostConfig']['NetworkMode']!='host' for s in states),
                'No privileged/host networking or published ports','Inspected all six HostConfig records')
        addresses={'gw-hq':{'wan':f'172.16.{g}.10','hq':f'10.{g}.1.1'},'gw-branch':{'wan':f'172.16.{g}.20','branch':f'10.{g}.2.1'},
                   'web-hq':{'hq':f'10.{g}.1.10'},'kdc':{'hq':f'10.{g}.1.20'},'client-br':{'branch':f'10.{g}.2.10'},'attacker':{'wan':f'172.16.{g}.66'}}
        for role,state in roles.items():
            actual={k.removeprefix(project+'_'):v['IPAddress'] for k,v in state['NetworkSettings']['Networks'].items()}
            require('M1-IP/'+role,actual==addresses[role],addresses[role],actual)
            mount=next(m for m in state['Mounts'] if m['Destination']=='/work')
            require('M1-MOUNT/'+role,not mount['RW'] and not any(m['Destination']=='/var/run/docker.sock' for m in state['Mounts']),'/work read-only, no Docker socket',{'work_rw':mount['RW']})
            routes=node(role,'ip','-4','route').stdout
            require('M1-NO-DEFAULT/'+role,not any(line.startswith('default ') for line in routes.splitlines()),'No external default route',routes)
            unreachable=node(role,'ip','route','get','192.0.2.1',expected=None)
            require('M1-EGRESS-ROUTE/'+role,unreachable.returncode!=0,'Documentation-only external destination has no route (no packet sent)',unreachable.stderr.strip())
            firewall=node(role,'iptables','-S').stdout
            require('M1-EGRESS-FILTER/'+role,'-P OUTPUT DROP' in firewall and '-A OUTPUT -d 127.0.0.11/32 -j DROP' in firewall,
                    'Default-drop output plus embedded DNS block',firewall)
        netids=command([cli,'network','ls','-q','--filter',f'label=com.docker.compose.project={project}']).stdout.split()
        nets=json.loads(command([cli,'network','inspect',*netids]).stdout)
        require('M1-NETWORKS',len(nets)==3 and all(n['Internal'] and n['Options'].get('com.docker.network.bridge.enable_ip_masquerade')=='false' and n['Options'].get('com.docker.network.bridge.gateway_mode_ipv4')=='isolated' for n in nets),
                'Three internal/isolated networks, masquerading disabled',{n['Name']:{'internal':n['Internal'],'options':n['Options']} for n in nets})
        host_rules=command([sys.executable,str(ROOT/'lab/host_l2_transit.py'),'--show']).stdout
        bridges={'br-'+n['Id'][:12] for n in nets}
        allowed={(f'10.{g}.0.0/16',f'10.{g}.0.0/16'),(f'172.16.{g}.66/32',f'10.{g}.2.0/24'),(f'10.{g}.2.0/24',f'172.16.{g}.66/32')}
        accepts=[shlex.split(line) for line in host_rules.splitlines() if line.startswith('-A ') and '-j ACCEPT' in line]
        scope_ok=len(accepts)==9 and all(rule[rule.index('-i')+1] in bridges and rule[rule.index('-i')+1]==rule[rule.index('-o')+1]
             and (rule[rule.index('-s')+1],rule[rule.index('-d')+1]) in allowed for rule in accepts)
        require('M1-HOST-L2-SCOPE',scope_ok,'Nine accepts restricted to the same project bridge and permitted lab address pairs',host_rules)
        for role in ('gw-hq','gw-branch'):
            policy=node(role,'ip','xfrm','policy').stdout
            daemon=node(role,'pgrep','-x','charon',expected=None)
            require('M1-NO-VPN/'+role,not policy.strip() and daemon.returncode==1,'No XFRM policy or charon process',{'policy':policy,'charon_exit':daemon.returncode})
            node(role,'iptables','-S')
        hq_route=node('attacker','ip','route','get',f'10.{g}.1.10',expected=None)
        require('M1-ATTACKER-HQ',hq_route.returncode!=0,'Attacker has no HQ route',hq_route.stderr.strip())
        node('attacker','ping','-c','1','-W','2',f'10.{g}.2.10')
        marker=f'SCP-M1-G{gid}-HTTP-CLEAR'
        report['versions']={
            'docker':command([cli,'version','--format','{{json .}}']).stdout,
            'compose':dc('version').stdout,
            'image_id':roles['gw-hq']['Image'],
            'lab_tools':node('gw-hq','bash','-lc',"openssl version; python3 --version; nginx -v 2>&1; tshark --version | head -n 1; dpkg-query -W openssl strongswan-swanctl python3-cryptography tcpdump tshark nginx; cat /opt/testssl-source-commit.txt").stdout}
        iface=node('gw-hq','bash','/opt/scp/roles/wan-iface.sh').stdout.strip()
        report['wan_interface']=iface
        if args.capture:
            transcript=open(LOGS/'M1_capture_console.txt','w',encoding='utf-8')
            tester='Scripted run requested by '+args.requested_by+'; independent member retest pending'
            capture=subprocess.Popen(prefix+['exec','-T','-e','TESTER='+tester,'gw-hq','bash','/opt/scp/roles/capture-baseline.sh'],
                    cwd=ROOT/'lab',stdout=transcript,stderr=subprocess.STDOUT)
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                if capture.poll() is not None: raise RuntimeError('Capture stopped early; inspect M1_capture_console.txt')
                if PCAP.exists() and PCAP.stat().st_size>=24: break
                time.sleep(.25)
            else: raise RuntimeError('tcpdump did not become ready')
        result=node('client-br','bash','/opt/scp/roles/verify-baseline.sh',timeout=20)
        require('M1-HTTP',marker in result.stdout,'HTTP success with exact synthetic marker',result.stdout)
        if capture:
            # Give the final TCP teardown a bounded chance to reach the capture.
            time.sleep(.5)
            node('gw-hq','pkill','-INT','-x','tcpdump')
            capture.wait(timeout=15)
            require('M1-CAPTURE-EXIT',capture.returncode==0,'tcpdump closed normally after SIGINT',capture.returncode)
            capture=None
            transcript.close(); transcript=None
        require('M1-PCAP',PCAP.exists() and PCAP.stat().st_size>24 and marker.encode() in PCAP.read_bytes(),
                'Real nonempty PCAP contains known readable HTTP response',{'exists':PCAP.exists(),'bytes':PCAP.stat().st_size if PCAP.exists() else 0})
        capture_path='/evidence/pcaps/M1_baseline_wan.pcap'
        fields=['frame.number','frame.time_epoch','ip.src','ip.dst','tcp.stream','http.request.method','http.request.uri','http.response.code']
        packets=node('gw-hq','tshark','-r',capture_path,'-Y','http.request or http.response','-T','fields',*[a for field in fields for a in ('-e',field)]).stdout
        report['http_fields']=fields; report['http_packets']=[line.split('\t') for line in packets.splitlines()]
        require('M1-HTTP-FRAMES',any(row[5]=='GET' for row in report['http_packets']) and any(len(row)>7 and row[7]=='200' for row in report['http_packets']),
                'Actual decoded GET and HTTP 200 frame numbers',report['http_packets'])
        frames=node('gw-hq','tshark','-r',capture_path,'-Y',f'tcp contains "{marker}"','-T','fields','-e','frame.number').stdout.split()
        require('M1-BODY-FRAMES',bool(frames),'Known marker visible in packet payload',frames)
        stream=report['http_packets'][0][4]
        follow=node('gw-hq','tshark','-r',capture_path,'-q','-z',f'follow,tcp,ascii,{stream}').stdout
        require('M1-PLAINTEXT',marker in follow,'Known marker readable in reassembled WAN TCP stream',follow)
        report['pcap']={'path':'evidence/pcaps/M1_baseline_wan.pcap','bytes':PCAP.stat().st_size,
            'sha256':hashlib.sha256(PCAP.read_bytes()).hexdigest(),'known_marker':marker,'body_frames':frames,'tcp_stream':stream,
            'capture_filter':f'host 10.{g}.2.10 and host 10.{g}.1.10 and tcp port 80'}
        report['result']='PASS'
    except Exception as error:
        report['result']='FAIL'; report['error']=str(error)
        print('FAIL:',error)
    finally:
        if capture and capture.poll() is None:
            subprocess.run(prefix+['exec','-T','gw-hq','pkill','-INT','-x','tcpdump'],capture_output=True,timeout=10)
            try: capture.wait(timeout=10)
            except subprocess.TimeoutExpired: capture.terminate()
        if transcript: transcript.close()
        report['utc_end']=datetime.now(timezone.utc).isoformat()
        (LOGS/'M1_runtime_checks.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f"M1 runtime {report['result']}: {len(report['checks'])} checks; see evidence/sanitized_logs/M1_runtime_checks.json")
    if report['result']!='PASS': raise SystemExit(1)

if __name__=='__main__': main()
