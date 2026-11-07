# M1 baseline WAN review

Result: PASS for the scripted M1 runtime and capture checks. Independent student review/retest is not claimed.
Requested by: student 2350906014. Execution: project scripted runner, with exact commands/outputs in M1_runtime_checks.json.

## Capture provenance
- Actual capture start: 2026-11-07T20:37:27+00:00 UTC / 07/11/2026 23:37:27 Asia/Amman (UTC+03).
- Node/interface: gw-hq, eth1 assigned 172.16.3.10/24. Interface discovered by wan-iface.sh, not assumed.
- File: evidence/pcaps/M1_baseline_wan.pcap; 10 packets, 1221 bytes.
- Capture filter: `host 10.3.2.10 and host 10.3.1.10 and tcp port 80`.
- Command: `tcpdump -i eth1 -nn -s 0 -U -w /evidence/pcaps/M1_baseline_wan.pcap "host 10.3.2.10 and host 10.3.1.10 and tcp port 80"`.
- Capture was stopped with SIGINT after the HTTP response; tcpdump reported 10 captured, 10 received by filter, 0 dropped. See M1_capture_console.txt.
- SHA-256: `9d2a6dc6646d15deb81ebe6109535b3dc6d3cbb3dbfad7ccd39f3aea7c53ee9d`.

## Expected and actual
Expected: six healthy nodes, explicit lab-only routes, no external default route/NAT/host port, no VPN policy/daemon, and readable HTTP across gw-hq WAN.
Actual: all 44 current runtime checks passed. This revalidation used the existing immutable PCAP; it did not replace the original capture.

| Evidence | Actual result |
| --- | --- |
| Request | Frame 4, 10.3.2.10 -> 10.3.1.10, GET /baseline.txt |
| Response | Frame 6, 10.3.1.10 -> 10.3.2.10, HTTP 200 |
| Readable body | Frame 6: SCP-M1-G03-HTTP-CLEAR |
| TCP stream | 0 |
| Trust boundary | Original campus addresses visible on gw-hq WAN; no NAT/VPN conceals the HTTP body |

## Repeatable commands
From lab/: `docker compose up -d --no-build --wait`.
From the project root with an available Python interpreter: `python lab/host_l2_transit.py --apply`, then `python tools/run_m1_baseline.py --requested-by ACTUAL_REQUESTER`.
The existing capture is protected. A deliberately new capture uses `--capture` only after the previous file has been safely archived; the runner refuses overwriting evidence.

Inspection: `docker compose exec -T gw-hq tshark -r /evidence/pcaps/M1_baseline_wan.pcap -Y 'http.request or http.response' -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.stream -e http.request.method -e http.request.uri -e http.response.code`.
Body search: `docker compose exec -T gw-hq tshark -r /evidence/pcaps/M1_baseline_wan.pcap -Y 'tcp contains "SCP-M1-G03-HTTP-CLEAR"' -T fields -e frame.number`.
Stream: `docker compose exec -T gw-hq tshark -r /evidence/pcaps/M1_baseline_wan.pcap -q -z follow,tcp,ascii,0`.

## Problems found and fixed
1. Compose mapping keys did not interpolate group variables in extra_hosts. Changed to interpolated list values; official config parsing now passes.
2. swanctl --version attempted VICI during image build and returned an error without charon. Used a package-version check and added standard strongSwan plugins. No IKE daemon was started for the build or baseline.
3. Docker DOCKER-INTERNAL dropped off-subnet packets before the router container. Internal/isolated networks are retained; the project-owned DOCKER-USER chain permits only same-SCP-bridge lab address pairs. No global firewall policy/sysctl or external interface was changed. Current rule scope is validated in the runtime report.

## Limits and release state
The filter intentionally selects HTTP only. It proves readable HTTP on the WAN, not the absence of every other protocol. No M2 TLS/PKI or M3 VPN/KDC/attack test is claimed. Public repository visibility, replacement-kit acceptance, original deadline handling and member review remain disclosed acceptance items; no M1 tag is created.

## Actual readable TCP stream
```text
===================================================================
Follow: tcp,ascii
Filter: tcp.stream eq 0
Node 0: 10.3.2.10:42840
Node 1: 10.3.1.10:80
93
GET /baseline.txt HTTP/1.1
Host: portal.g03.scp.lab
User-Agent: curl/8.5.0
Accept: */*


	268
HTTP/1.1 200 OK
Server: nginx/1.24.0 (Ubuntu)
Date: Sat, 07 Nov 2026 20:37:28 GMT
Content-Type: text/plain
Content-Length: 22
Last-Modified: Sat, 07 Nov 2026 20:30:14 GMT
Connection: keep-alive
ETag: "6aef8a56-16"
Accept-Ranges: bytes

SCP-M1-G03-HTTP-CLEAR

===================================================================
```
