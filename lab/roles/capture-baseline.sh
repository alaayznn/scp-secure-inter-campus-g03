#!/usr/bin/env bash
# Deliberate future action only: run on gw-hq, then generate HTTP from client-br.
set -euo pipefail
[[ "$ROLE" == gw-hq ]] || { echo 'Run on gw-hq only' >&2; exit 1; }
: "${TESTER:?Set TESTER to actual operator name or student ID}"
[[ -z "$(ip xfrm policy)" ]] || { echo 'IPsec policy present; refuse baseline' >&2; exit 1; }
iface=$(bash /opt/scp/roles/wan-iface.sh)
output=/evidence/pcaps/M1_baseline_wan.pcap
[[ ! -e "$output" ]] || { echo 'Existing evidence preserved; review it before any replacement' >&2; exit 1; }
mkdir -p /evidence/pcaps /evidence/sanitized_logs
filter="host 10.$GROUP_NUM.2.10 and host 10.$GROUP_NUM.1.10 and tcp port 80"
{
    date -u '+UTC start: %Y-%m-%dT%H:%M:%SZ'
    printf 'Tester: %s\nRole: gw-hq\nInterface: %s\nCapture filter: %s\n' "$TESTER" "$iface" "$filter"
    printf 'Command: tcpdump -i %s -nn -s 0 -U -w %s %s\n' "$iface" "$output" "$filter"
    ip -o -4 addr show dev "$iface"
} > /evidence/sanitized_logs/M1_capture_session.txt
echo "Capturing real WAN $iface. Generate HTTP in another terminal, then Ctrl+C here."
tcpdump -i "$iface" -nn -s 0 -U -w "$output" "$filter"
