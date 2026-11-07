#!/usr/bin/env bash
set -euo pipefail
[[ "${LAB_MODE:-}" == baseline ]] || { echo 'M1 supports baseline only' >&2; exit 1; }
[[ "${GROUP_ID:-}" =~ ^[0-9]{2}$ && "${GROUP_NUM:-}" =~ ^[1-9][0-9]?$ ]] || exit 2
[[ "$GROUP_NUM" == "$((10#$GROUP_ID))" ]] || { echo 'Group ID/number mismatch' >&2; exit 2; }
g=$GROUP_NUM
hq="10.$g.1.0/24"; br="10.$g.2.0/24"; wan="172.16.$g.0/24"
iface_for() { ip -o -4 addr show | awk -v a="$1/24" '$4==a {print $2}'; }
# No external default route or alternate Internet path. No NAT rules.
while ip route del default 2>/dev/null; do :; done
iptables -F; iptables -X
iptables -P INPUT DROP; iptables -P FORWARD DROP; iptables -P OUTPUT DROP
# Stop embedded Docker DNS from proxying off-lab questions via loopback.
iptables -A OUTPUT -d 127.0.0.11/32 -j DROP
iptables -A INPUT -i lo -j ACCEPT; iptables -A OUTPUT -o lo -j ACCEPT
for subnet in "$hq" "$br" "$wan"; do
    iptables -A INPUT -s "$subnet" -j ACCEPT
    iptables -A OUTPUT -d "$subnet" -j ACCEPT
done
# Docker DNS is not needed: every required name is mapped through extra_hosts.
case "$ROLE" in
  gw-hq)
    ip route replace "$br" via "172.16.$g.20"
    w=$(iface_for "172.16.$g.10"); l=$(iface_for "10.$g.1.1")
    [[ -n "$w" && -n "$l" ]]
    iptables -A FORWARD -i "$w" -o "$l" -s "10.$g.2.10" -d "10.$g.1.10" -p tcp --dport 80 -j ACCEPT
    iptables -A FORWARD -i "$l" -o "$w" -s "10.$g.1.10" -d "10.$g.2.10" -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$w" -o "$l" -s "10.$g.2.10" -d "10.$g.1.10" -p icmp -j ACCEPT
    iptables -A FORWARD -i "$l" -o "$w" -s "10.$g.1.10" -d "10.$g.2.10" -p icmp -j ACCEPT
    ;;
  gw-branch)
    ip route replace "$hq" via "172.16.$g.10"
    w=$(iface_for "172.16.$g.20"); l=$(iface_for "10.$g.2.1")
    [[ -n "$w" && -n "$l" ]]
    iptables -A FORWARD -i "$l" -o "$w" -s "10.$g.2.10" -d "10.$g.1.10" -p tcp --dport 80 -j ACCEPT
    iptables -A FORWARD -i "$w" -o "$l" -s "10.$g.1.10" -d "10.$g.2.10" -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
    iptables -A FORWARD -i "$l" -o "$w" -s "10.$g.2.10" -d "10.$g.1.10" -p icmp -j ACCEPT
    iptables -A FORWARD -i "$w" -o "$l" -s "10.$g.1.10" -d "10.$g.2.10" -p icmp -j ACCEPT
    iptables -A FORWARD -i "$w" -o "$l" -s "172.16.$g.66" -d "$br" -j ACCEPT
    iptables -A FORWARD -i "$l" -o "$w" -s "$br" -d "172.16.$g.66" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    ;;
  web-hq|kdc)
    ip route replace "$br" via "10.$g.1.1"
    ;;
  client-br)
    ip route replace "$hq" via "10.$g.2.1"
    ip route replace "$wan" via "10.$g.2.1"
    ;;
  attacker)
    ip route replace "$br" via "172.16.$g.20"
    ;;
  *) echo 'Unknown lab role' >&2; exit 2 ;;
esac
# Explicitly refuse future VPN files in this M1 baseline. Do not load strongSwan.
if [[ "$ROLE" == gw-hq || "$ROLE" == gw-branch ]]; then
    [[ ! -f "/work/ipsec/$ROLE/swanctl.conf" ]] || { echo 'VPN file exists: refuse ambiguous baseline' >&2; exit 3; }
    [[ -z "$(ip xfrm policy)" ]] || { echo 'Existing IPsec policy: refuse baseline' >&2; exit 3; }
fi
if [[ "$ROLE" == web-hq ]]; then
    mkdir -p /run/scp-www
    printf 'SCP-M1-G%s-HTTP-CLEAR\n' "$GROUP_ID" > /run/scp-www/baseline.txt
    cat > /run/scp-nginx.conf <<'NGINX'
user www-data;
worker_processes 1;
pid /run/nginx.pid;
error_log /dev/stderr info;
events { worker_connections 128; }
http {
    access_log /dev/stdout;
    server {
        listen 80;
        server_name _;
        root /run/scp-www;
        default_type text/plain;
        location = /baseline.txt { try_files $uri =404; }
        location / { return 404; }
    }
}
NGINX
    nginx -t -c /run/scp-nginx.conf
    touch /run/scp-baseline-ready
    exec nginx -c /run/scp-nginx.conf -g 'daemon off;'
fi
touch /run/scp-baseline-ready
exec sleep infinity
