#!/usr/bin/env bash
# Run inside client-br only, after explicit permission to start the lab.
set -euo pipefail
[[ "$ROLE" == client-br ]] || { echo 'Run on client-br' >&2; exit 1; }
ip -4 addr; ip -4 route
[[ -z "$(ip route show default)" ]]
ping -c 2 -W 2 "10.$GROUP_NUM.1.10"
body=$(curl --fail --silent --show-error --noproxy '*' --connect-timeout 5 --max-time 10 \
    "http://portal.g${GROUP_ID}.scp.lab/baseline.txt")
[[ "$body" == "SCP-M1-G${GROUP_ID}-HTTP-CLEAR" ]]
printf '%s\n' "$body"
echo 'HTTP client result OK; this alone does not prove WAN capture or isolation.'
