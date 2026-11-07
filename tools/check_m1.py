"""Meaningful static M1 consistency checks. Never executes role scripts or Docker."""
import json
import hashlib
import os
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from pypdf import PdfReader

ROOT = Path(__file__).resolve().parents[1]
checks=[]
def check(name, condition, detail):
    checks.append({'check': name, 'result': 'PASS' if condition else 'FAIL', 'detail': detail})

def main():
    cfg=json.loads((ROOT/'project.json').read_text(encoding='utf-8'))
    gid=cfg['group_id']; g=str(int(gid))
    check('confirmed_group', gid=='03' and g=='3', 'User confirmed G3; normalized 03/3.')
    check('member_records', len(cfg['members'])==2 and cfg['group_size_exception_approved'] is True,
          'Two names/IDs supplied by user; user reports instructor approval for two-member exception only.')
    compose=json.loads((ROOT/'lab/docker-compose.yml').read_text(encoding='utf-8'))
    services=compose['services']; nets=compose['networks']
    expected={'gw-hq','gw-branch','web-hq','kdc','client-br','attacker'}
    check('six_nodes_three_networks', set(services)==expected and set(nets)=={'wan','hq','branch'}, 'Exact node/network inventory checked.')
    check('network_isolation_declarations', all(n['internal'] is True and n['enable_ipv6'] is False and n['driver_opts']['com.docker.network.bridge.enable_ip_masquerade']=='false' for n in nets.values()), 'Static declarations only; not runtime proof.')
    check('isolated_bridge_mode',all(n['driver_opts'].get('com.docker.network.bridge.gateway_mode_ipv4')=='isolated' for n in nets.values()),'No host IPv4 bridge address; runtime tests separately verify scoped L2 transit.')
    check('no_host_exposure', all(not any(k in s for k in ('ports','network_mode','privileged')) and not any('docker.sock' in v for v in s['volumes']) for s in services.values()), 'No published port, host network, privileged flag or Docker socket.')
    check('mount_scope', all('..:/work:ro' in s['volumes'] for s in services.values()) and sum('../evidence:/evidence:rw' in s['volumes'] for s in services.values())==1 and '../evidence:/evidence:rw' in services['gw-hq']['volumes'], 'Repository read-only everywhere; only gw-hq evidence writable. Root key must be outside repository.')
    token='${GROUP_NUM:?Copy .env.example to .env and verify GROUP_NUM}'
    expected_ip={'gw-hq':{'wan':f'172.16.{token}.10','hq':f'10.{token}.1.1'},'gw-branch':{'wan':f'172.16.{token}.20','branch':f'10.{token}.2.1'},'web-hq':{'hq':f'10.{token}.1.10'},'kdc':{'hq':f'10.{token}.1.20'},'client-br':{'branch':f'10.{token}.2.10'},'attacker':{'wan':f'172.16.{token}.66'}}
    check('address_and_attachment_plan', all({n:v['ipv4_address'] for n,v in services[r]['networks'].items()}==v for r,v in expected_ip.items()), 'Exact specification suffixes checked, including attacker WAN-only.')
    env=(ROOT/'lab/.env.example').read_text()
    check('group_env_example', 'GROUP_ID=03\n' in env and 'GROUP_NUM=3\n' in env, 'Example uses real group. A real .env is local-only and excluded by .gitignore.')
    docker=shutil.which('docker')
    if not docker and os.environ.get('LOCALAPPDATA'):
        candidate=Path(os.environ['LOCALAPPDATA'])/'Programs/DockerDesktop/resources/bin/docker.exe'
        docker=str(candidate) if candidate.is_file() else None
    if docker and (ROOT/'lab/.env').exists():
        rendered=subprocess.run([docker,'compose','--project-directory',str(ROOT/'lab'),'-f',str(ROOT/'lab/docker-compose.yml'),'--env-file',str(ROOT/'lab/.env'),'config','--format','json'],capture_output=True,text=True,encoding='utf-8',timeout=30)
        check('official_compose_schema',rendered.returncode==0,'Official Compose config parser; client-only operation, no engine or container startup.')
        if rendered.returncode==0:
            resolved=json.loads(rendered.stdout)
            hosts=resolved['services']['client-br']['extra_hosts']
            if isinstance(hosts,list):
                hosts=dict(item.split('=',1) if '=' in item else item.split(':',1) for item in hosts)
            correct=(hosts.get('portal.g03.scp.lab')=='10.3.1.10' and hosts.get('pki.g03.scp.lab')=='10.3.1.10'
                and resolved['services']['gw-hq']['networks']['wan']['ipv4_address']=='172.16.3.10'
                and len(resolved['services'])==6 and all(n['internal'] for n in resolved['networks'].values()))
            check('compose_resolved_group_values',correct,'Group FQDNs/IPs and six services/three internal networks checked after interpolation.')
    else:
        checks.append({'check':'official_compose_schema','result':'NOT_TESTED','detail':'Requires an installed Docker CLI and local lab/.env; no installation or startup attempted by this checker.'})
    check('baseline_no_future_vpn', not (ROOT/'ipsec/gw-hq/swanctl.conf').exists() and not (ROOT/'ipsec/gw-branch/swanctl.conf').exists(), 'Fixed swanctl paths deliberately absent in M1.')
    entry=(ROOT/'lab/roles/baseline-entrypoint.sh').read_text()
    check('baseline_routes_and_marker', all(s in entry for s in ('172.16.$g.20','172.16.$g.10','10.$g.1.1','10.$g.2.1','SCP-M1-G%s-HTTP-CLEAR','ip route del default','ip xfrm policy','nginx -t')), 'Static route/marker/control declarations checked; shell not run.')
    bash=shutil.which('bash')
    if not bash:
        candidate=Path('C:/Program Files/Git/bin/bash.exe')
        bash=str(candidate) if candidate.exists() else None
    for script in sorted((ROOT/'lab/roles').glob('*.sh')):
        if bash:
            result=subprocess.run([bash,'-n',str(script)],capture_output=True,text=True)
            check('bash_syntax/'+script.name,result.returncode==0,result.stderr.strip() or 'bash -n only; no script execution.')
        else:
            checks.append({'check':'bash_syntax/'+script.name,'result':'NOT_TESTED','detail':'No Bash available.'})
    required=['M1_Requirements','M1_Topology_Trust','M1_PKI_Design','M1_ProtocolDesign','M1_STRIDE','M1_TeamPlan']
    texts={}; pagecounts={}
    for name in required:
        pdf=ROOT/'docs/M1'/f'{name}.pdf'; src=ROOT/'docs/M1/source'/f'{name}.md'
        check('deliverable/'+name,pdf.is_file() and src.is_file(),'PDF and editable Markdown retained.')
        if pdf.exists():
            reader=PdfReader(pdf); pagecounts[name]=len(reader.pages)
            texts[name]='\n'.join(p.extract_text() or '' for p in reader.pages)
            check('pdf_text_and_pages/'+name,all((p.extract_text() or '').strip() for p in reader.pages),'All pages have extractable text; visual review is separate.')
    req=texts.get('M1_Requirements','')
    check('fr_sr_coverage',all(f'FR{i:02}' in req for i in range(1,13)) and all(f'SR{i:02}' in req for i in range(1,15)), 'FR01-12 and SR01-14 present.')
    alltext='\n'.join(texts.values())
    check('no_example_group_07', not re.search(r'g07\b|10\.7\.|172\.16\.7\.',alltext), 'No example group 07 identities/addresses in PDFs.')
    topo=texts.get('M1_Topology_Trust','')
    check('actual_group_pdf_addresses',all(s in topo for s in ('10.3.1.10','10.3.2.10','172.16.3.10','172.16.3.20','172.16.3.66','portal.g03.scp.lab')), 'Actual G3 values extracted from final PDF.')
    stride=texts.get('M1_STRIDE','')
    check('lab_threat_count',all(f'S{i:02}' in stride for i in range(1,15)),'14 threat entries, >=8 required; contents reviewed separately.')
    package=ROOT/'docs/M1/M1_Submission.pdf'
    if package.exists():
        reader=PdfReader(package)
        uris={str(a.get_object().get('/A',{}).get('/URI')) for page in reader.pages for a in page.get('/Annots',[]) if a.get_object().get('/A',{}).get('/URI')}
        repo=cfg.get('repository',{}).get('url')
        check('submission_links_and_bookmarks',repo in uris and len(reader.outline)==7 and len(reader.pages)>sum(pagecounts.values()),
              'Combined PDF includes cover, all six documents, seven section bookmarks and clickable repository URI.')
        pagecounts['M1_Submission']=len(reader.pages)
    capture=ROOT/'evidence/pcaps/M1_baseline_wan.pcap'
    runtime_path=ROOT/'evidence/sanitized_logs/M1_runtime_checks.json'
    if capture.exists() and runtime_path.exists():
        runtime=json.loads(runtime_path.read_text(encoding='utf-8'))
        integrity=(runtime.get('result')=='PASS' and capture.stat().st_size>24 and runtime.get('pcap',{}).get('sha256')==hashlib.sha256(capture.read_bytes()).hexdigest()
            and f'SCP-M1-G{gid}-HTTP-CLEAR'.encode() in capture.read_bytes())
        check('baseline_capture_integrity',integrity,'Real PCAP hash/body consistent with recorded successful runtime analysis; static integrity is not independent provenance review.')
    else:
        check('baseline_capture_pending',not capture.exists(),'No capture has been supplied; runtime acceptance remains pending. This check does not claim capture acceptance.')
    path=ROOT/'evidence/sanitized_logs/M1_static_review.json'; path.parent.mkdir(parents=True,exist_ok=True)
    hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/'docs/M1').glob('*.pdf')}
    visual={'status':'PENDING','method':'Render all final PDF pages with bundled Poppler, inspect diagrams/tables/names, then record observed result.'}
    if path.exists():
        previous=json.loads(path.read_text(encoding='utf-8'))
        if previous.get('pdf_sha256')==hashes:
            visual=previous.get('visual_review',visual)
    log={'utc':datetime.now(timezone.utc).isoformat(),'scope':'STATIC AND COMPOSE CONFIG ONLY where available; no image build/runtime/packet capture performed','checks':checks,'pdf_pages':pagecounts,'pdf_sha256':hashes,'visual_review':visual}
    path.write_text(json.dumps(log,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    print(f'{len(checks)} static checks; failures: {sum(c["result"]=="FAIL" for c in checks)}. Runtime validation is recorded separately.')
    for c in checks:
        if c['result']!='PASS': print(c)
    if any(c['result']=='FAIL' for c in checks): raise SystemExit(1)

if __name__=='__main__': main()
