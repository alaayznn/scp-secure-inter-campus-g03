# Independently authored M1 baseline lab

**NOT RUN OR BUILT.** Installation, image download and lab operation were authorized on 07/11/2026. WSL and Docker Desktop are installed; Windows still requires a manual restart before WSL2 can start. Docker CLI/Compose are available and official Compose configuration validation passes. No Ubuntu image has been built/pulled and no lab has run. Group 03 / G=3 is confirmed. These are project-local replacement files, not the instructor's Starter Kit. The assignment section 12 prohibits lab/ modifications without written instructor approval. No acceptance of this replacement is claimed.

Six containers, three internal bridge networks; no published ports, host networking, Docker socket, privileged mode, NAT or external runtime default routes. `internal: true` isolates networks; masquerading is also explicitly disabled. Embedded DNS 127.0.0.11 is blocked before the loopback allow rule; required names use static hosts entries. Host/Docker administrators and operators who can change network capabilities remain trusted. The entire repository is mounted read-only at `/work`, so ALL future secrets including the Root key must be created outside it. Only gw-hq receives writable `/evidence` for captures. Additional role-specific secret mounts belong to later stages. Roles use scoped Linux capabilities to set routes/firewalls and capture traffic. This baseline is not final gateway hardening.

`docker-compose.yml` is formatted as JSON-compatible YAML 1.2 so existing Python can inspect it without installing a YAML parser. Compose v2 accepts this representation. `tools/configure_lab.py` rebuilds it and `.env.example` from confirmed `project.json`; neither builds nor runs Docker. Do not overwrite manual Compose edits without reviewing them first.

## Image and tooling

Dockerfile uses Ubuntu 24.04, distribution OpenSSL 3, nginx, strongSwan/swanctl 5.9+, Python 3.12 + cryptography, tcpdump/tshark, nmap, curl and testssl.sh tag v3.2.1. Build needs Internet once later; runtime needs none. No dependency has been downloaded by this preparation task. No daemon starts from package installation; entrypoint starts only baseline nginx on web-hq and idles other nodes. No swanctl or KDC is launched.

Ubuntu tag and apt security updates are not digest/package-version locked. Record the actual base digest, `/opt/scp-image-packages.txt`, `/opt/testssl-source-commit.txt`, `openssl version`, `swanctl --version`, `python3 --version`, `nginx -v` and `tshark --version` at the first authorized build. Verify strongSwan >=5.9. This is a rebuild recipe, not a claim of byte-identical images. swanctl can warn about missing charon during image version checks; assess actual build behavior later. Dockerfile/package installation and Linux runtime remain untested.

## Later setup (PowerShell on Windows, not yet executed)

Requirements: Windows virtualization/WSL2 backend and Docker Desktop with Compose v2; Git exists. Do not auto-reboot. Install missing software only after user permission. In a terminal:

```powershell
Set-Location 'D:\SCP project\lab'
Copy-Item .env.example .env  # Only if .env does not already exist; preserve existing local values.
Get-Content .env             # Must show GROUP_ID=03 and GROUP_NUM=3, no secrets.
docker version
docker compose version
docker compose config --quiet
docker compose build
docker compose up -d --no-build
docker compose ps
```

All six services must be running/healthy. If subnets overlap another local network, stop and investigate; do not silently change assigned addresses. Build Internet access is separate from runtime isolation. Never add an external runtime network just to make a lab command work.

## Later live validation

```powershell
docker compose exec client-br bash /opt/scp/roles/verify-baseline.sh
docker compose exec gw-hq bash -lc 'ip -4 addr; ip -4 route; iptables -S; ip xfrm policy; pgrep -a charon || true'
docker compose exec gw-branch bash -lc 'ip -4 addr; ip -4 route; iptables -S; ip xfrm policy'
docker compose exec attacker ip -4 route
docker compose exec web-hq bash -lc 'ip -4 route; ss -lntp'
```

Expected marker: `SCP-M1-G03-HTTP-CLEAR`. Expected client/server: 10.3.2.10 -> 10.3.1.10:80. Expected HTTP traversal is client -> branch gateway -> WAN -> HQ gateway -> web; no NAT. Prove route with both routing tables and the WAN capture; a successful curl alone is not enough. No charon, no XFRM policy, no TCP 443 yet. Ping from client to web is permitted.

Inspect all three created networks using `docker network ls --filter label=com.docker.compose.project=scp-g03-m1` then `docker network inspect <each actual network name>`. Require Internal=true, enable_ip_masquerade=false, correct IPAM/membership and no extra network or host port. Inspect `ip route` on every node: no default route. `docker compose exec attacker ip route get 10.3.1.10` must report unreachable; explicit traffic sent to gw-hq from attacker must still be dropped by gw-hq. Attacker can reach Branch via 172.16.3.20. If route/forwarding isolation behaves differently on Docker Desktop, stop and fix/document before collecting accepted evidence.

Safe egress check: inspect routes and rules, then use `ip route get 192.0.2.1` inside each node (documentation-only address; this does not send packets) and require unreachable. Do not scan or probe real outside networks. Host administrators can bypass container controls; this is not a sandbox against a malicious host owner.

## Later real WAN capture (two terminals)

First terminal in lab/, use actual tester ID rather than an invented identity:

```powershell
docker compose exec -e TESTER=ACTUAL_STUDENT_ID gw-hq bash /opt/scp/roles/capture-baseline.sh
```

The script finds the interface assigned 172.16.3.10/24, refuses existing PCAP or IPsec policy, records real start time/tester/interface/filter, then runs tcpdump. It has NOT been run. Second terminal in lab/:

```powershell
docker compose exec client-br bash /opt/scp/roles/verify-baseline.sh
```

Stop the capture with Ctrl+C in the first terminal after the complete HTTP response. Required real file is `evidence/pcaps/M1_baseline_wan.pcap` in the project root. No placeholder capture is supplied. Capture filter: `host 10.3.2.10 and host 10.3.1.10 and tcp port 80`. Use `-s 0` for full payload. This filtered capture demonstrates HTTP only; it does not prove the absence of all other traffic. M3's broader IKE/ESP confidentiality capture is separate future work.

## Later inspect and record evidence

```powershell
docker compose exec gw-hq tshark -r /evidence/pcaps/M1_baseline_wan.pcap -Y 'http.request or http.response' -T fields -e frame.number -e frame.time_utc -e ip.src -e ip.dst -e tcp.stream -e http.request.method -e http.request.uri -e http.response.code
docker compose exec gw-hq tshark -r /evidence/pcaps/M1_baseline_wan.pcap -Y 'tcp contains "SCP-M1-G03-HTTP-CLEAR"' -T fields -e frame.number -e ip.src -e ip.dst -e tcp.payload
docker compose exec gw-hq tshark -r /evidence/pcaps/M1_baseline_wan.pcap -q -z follow,tcp,ascii,0
Get-FileHash ..\evidence\pcaps\M1_baseline_wan.pcap -Algorithm SHA256
```

If traffic uses a stream other than 0, choose the actual `tcp.stream`. If response segmentation prevents a per-packet string match, inspect the reassembled stream and document the contributing frame numbers. Require HTTP request, 200 response and visible exact marker in payload, with original client/server addresses. Record actual request/response/body frame numbers (not invented numbers), command outputs, interface, filter, date, actual tester, capture hash and expected vs actual result in `evidence/sanitized_logs/M1_baseline_review.md` AFTER the test. A PCAP header, empty capture, ping-only trace or screenshot is insufficient. Test-log instructions are in evidence/README.md.

## Stop / rebuild

```powershell
docker compose down
# Once authorized, rebuild after reviewing file changes:
docker compose build
docker compose up -d --no-build
```

Do not use destructive prune commands. `down` removes this Compose project's containers/networks; evidence remains on the host bind mount. Future VPN migration must deliberately replace the M1 clear forwarding rules with IPsec-policy-required fail-closed rules, supply the fixed gateway swanctl paths and test T9. Merely adding VPN on top of baseline rules is insufficient.

References: [Compose networks](https://docs.docker.com/reference/compose-file/networks/) and [bridge driver options](https://docs.docker.com/engine/network/drivers/bridge/); [testssl 3.2.1 release](https://github.com/testssl/testssl.sh/releases/tag/v3.2.1).
