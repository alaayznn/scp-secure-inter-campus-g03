"""Heuristic secret/path scan of worktree and all reachable history incl. reflogs.
Does not print matching credential contents. Not a substitute for manual review.
"""
import json
import argparse
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
PATTERNS={
    'private_key': re.compile(rb'-----BEGIN '+rb'(?:[A-Z0-9]+ )*PRIVATE KEY-----'),
    'github_token': re.compile(rb'\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b'),
    'aws_access_key': re.compile(rb'\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'),
    'assigned_secret': re.compile(rb'(?im)^\s*(?:password|passphrase|psk|api_key|access_token)\s*[:=]\s*[\x22\x27]?(?!ACTUAL_|REPLACE_|CHANGE_ME|\$|<)[^\s\x22\x27]{8,}')
}
def git(*args):
    r=subprocess.run(['git','-C',str(ROOT),*args],capture_output=True)
    if r.returncode: raise RuntimeError(r.stderr.decode(errors='replace').strip())
    return r.stdout

def forbidden(path):
    p=Path(path); low=path.lower().replace('\\','/'); n=p.name.lower()
    return ((n=='.env' or n.startswith('.env.') and n!='.env.example')
        or p.suffix.lower() in ('.key','.p12','.pfx','.jks','.keystore')
        or p.suffix.lower()=='.pem' and not n.endswith(('.public.pem','.cert.pem'))
        or any(x in n for x in ('keylog','key-log','passphrase','password','psk'))
        or any(x in low.split('/') for x in ('private','secrets')))

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check-only', action='store_true', help='Check without changing the stored scan snapshot')
    args=parser.parse_args()
    findings=[]; history_blobs=0; checked=0; seen=set()
    try:
        git('rev-parse','--git-dir'); hasgit=True
    except RuntimeError: hasgit=False
    if hasgit:
        paths=git('ls-files','--cached','--others','--exclude-standard','-z').decode().split('\0')
    else:
        paths=[p.relative_to(ROOT).as_posix() for p in ROOT.rglob('*') if p.is_file() and not set(p.relative_to(ROOT).parts)&{'.git','tmp','__pycache__'}]
    def scan(path,data,where):
        nonlocal checked
        checked+=1
        if forbidden(path): findings.append({'location':where,'path':path,'kind':'forbidden_path'})
        for label,pattern in PATTERNS.items():
            if pattern.search(data): findings.append({'location':where,'path':path,'kind':label})
    for path in sorted(set(p for p in paths if p)):
        p=ROOT/path
        if p.is_file(): scan(path,p.read_bytes(),'worktree')
    if hasgit:
        commits=git('rev-list','--all','--reflog').decode().splitlines()
        for commit in commits:
            for item in git('ls-tree','-r','-z',commit).split(b'\0'):
                if not item: continue
                meta,path=item.split(b'\t',1); sha=meta.split()[2].decode(); name=path.decode()
                key=(sha,name)
                if key in seen: continue
                seen.add(key); history_blobs+=1
                scan(name,git('cat-file','blob',sha),'history:'+commit[:12])
    result={'utc':datetime.now(timezone.utc).isoformat(),'scope':'Heuristic scan of nonignored current files and all reachable refs/reflog commits; manual review still required. No secrets printed.','files_or_blobs_checked':checked,'history_blobs_checked':history_blobs,'findings':findings,'result':'PASS' if not findings else 'FAIL'}
    dest=ROOT/'evidence/sanitized_logs/M1_secret_scan.json'; dest.parent.mkdir(parents=True,exist_ok=True)
    if not args.check_only:
        dest.write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
    print(f'Secret scan {result["result"]}: {checked} files/blobs, {history_blobs} historical; {len(findings)} findings.')
    for finding in findings: print(finding)
    if findings: raise SystemExit(1)

if __name__=='__main__': main()
