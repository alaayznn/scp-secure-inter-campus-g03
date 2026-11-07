"""Regenerate non-secret Compose/hosts metadata from confirmed project.json; no Docker calls."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

def main():
    config = json.loads((ROOT / 'project.json').read_text(encoding='utf-8'))
    gid = config['group_id']
    if not isinstance(gid, str) or len(gid) != 2 or not gid.isascii() or not gid.isdigit():
        raise SystemExit('Confirm a two-digit group_id in project.json first')
    g = int(gid)
    if not 1 <= g <= 99:
        raise SystemExit('This address template supports confirmed groups 01-99 only')
    (ROOT / 'lab/.env.example').write_text(f'# Confirmed group, not a password file. Copy to .env locally when ready.\nGROUP_ID={gid}\nGROUP_NUM={g}\n', encoding='utf-8')
    num = '${GROUP_NUM:?Copy .env.example to .env and verify GROUP_NUM}'
    two = '${GROUP_ID:?Copy .env.example to .env and verify GROUP_ID}'
    addresses = {
        'gw-hq': {'wan': f'172.16.{num}.10', 'hq': f'10.{num}.1.1'},
        'gw-branch': {'wan': f'172.16.{num}.20', 'branch': f'10.{num}.2.1'},
        'web-hq': {'hq': f'10.{num}.1.10'}, 'kdc': {'hq': f'10.{num}.1.20'},
        'client-br': {'branch': f'10.{num}.2.10'}, 'attacker': {'wan': f'172.16.{num}.66'},
    }
    host_ips = {n: next(iter(a.values())) for n, a in addresses.items()}
    host_ips.update({'web-hq': f'10.{num}.1.10', 'kdc': f'10.{num}.1.20'})
    services = {}
    for role, nets in addresses.items():
        hosts = {n: ip for n, ip in host_ips.items()}
        hosts.update({f'{n}.g{two}.scp.lab': ip for n, ip in host_ips.items()})
        hosts.update({f'portal.g{two}.scp.lab': host_ips['web-hq'], f'pki.g{two}.scp.lab': host_ips['web-hq']})
        svc = {
            'build': {'context': './docker'}, 'image': f'scp-g{two}-lab:ubuntu24.04-m1',
            'hostname': role, 'init': True, 'restart': 'no',
            'environment': {'ROLE': role, 'GROUP_ID': two, 'GROUP_NUM': num, 'LAB_MODE': 'baseline'},
            'cap_drop': ['ALL'],
            'cap_add': ['NET_ADMIN', 'NET_RAW', 'SETUID', 'SETGID', 'CHOWN', 'DAC_OVERRIDE', 'KILL'],
            'security_opt': ['no-new-privileges:true'],
            'sysctls': {'net.ipv4.ip_forward': '1' if role.startswith('gw-') else '0',
                         'net.ipv4.conf.all.rp_filter': '0', 'net.ipv4.conf.default.rp_filter': '0',
                         'net.ipv6.conf.all.disable_ipv6': '1'},
            'volumes': ['..:/work:ro', './roles:/opt/scp/roles:ro'],
            'extra_hosts': hosts,
            'networks': {n: {'ipv4_address': ip} for n, ip in nets.items()},
            'healthcheck': {'test': ['CMD', 'bash', '/opt/scp/roles/healthcheck.sh'],
                            'interval': '10s', 'timeout': '3s', 'retries': 6},
        }
        if role == 'gw-hq':
            svc['volumes'].append('../evidence:/evidence:rw')
        if role == 'web-hq':
            svc['cap_add'].append('NET_BIND_SERVICE')
        services[role] = svc
    nets = {}
    for name, prefix in [('wan', '172.16.' + num), ('hq', '10.' + num + '.1'), ('branch', '10.' + num + '.2')]:
        nets[name] = {'driver': 'bridge', 'internal': True, 'enable_ipv6': False,
                      'driver_opts': {'com.docker.network.bridge.enable_ip_masquerade': 'false'},
                      'ipam': {'config': [{'subnet': prefix + '.0/24', 'gateway': prefix + '.254'}]}}
    data = {'name': f'scp-g{two}-m1', 'services': services, 'networks': nets}
    # JSON is a YAML 1.2 subset, consumed by Compose v2 without a host YAML package.
    (ROOT / 'lab/docker-compose.yml').write_text(json.dumps(data, indent=2) + '\n', encoding='utf-8')
    print(f'Generated Compose and .env.example for confirmed G{gid} ({g}); no lab started.')

if __name__ == '__main__':
    main()
