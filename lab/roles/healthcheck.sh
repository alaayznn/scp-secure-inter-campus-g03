#!/usr/bin/env bash
set -euo pipefail
test -f /run/scp-baseline-ready
if [[ "$ROLE" == web-hq ]]; then
    curl --fail --silent --noproxy '*' http://127.0.0.1/baseline.txt | grep -Fx "SCP-M1-G${GROUP_ID}-HTTP-CLEAR"
fi
