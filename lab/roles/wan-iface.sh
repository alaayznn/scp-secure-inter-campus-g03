#!/usr/bin/env bash
set -euo pipefail
: "${GROUP_NUM:?GROUP_NUM required}"
iface=$(ip -o -4 addr show | awk -v addr="172.16.${GROUP_NUM}.10/24" '$4 == addr {print $2}')
[[ -n "$iface" && "$iface" != *$'\n'* ]] || { echo 'Exactly one gw-hq WAN interface required' >&2; exit 1; }
printf '%s\n' "$iface"
