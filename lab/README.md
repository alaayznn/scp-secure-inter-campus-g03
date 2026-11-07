# Verified M1 baseline lab

**BUILT AND TESTED on 07/11/2026.** Six nodes were healthy and the real gw-hq WAN HTTP capture passed analysis. Group 03 / G=3 is confirmed. These are project-local replacement files, not the instructor's Starter Kit. Assignment section 12 prohibits lab/ modifications without written instructor approval; acceptance of this replacement is not claimed. The Public repository requested by the team is also an exception to the specified private visibility.

Six containers, three internal/isolated bridge networks; no published ports, host networking, Docker socket, privileged mode, NAT or external runtime default routes. Gateway mode `isolated` removes host IPv4 bridge addresses; IPAM .254 remains reserved, not a campus gateway. Masquerading is explicitly disabled. Embedded DNS 127.0.0.11 is blocked before the loopback allow rule; required names use static hosts entries. Host/Docker administrators remain trusted. Repository mount `/work` is read-only everywhere, so ALL future secrets including the Root key must be outside it. Only gw-hq receives writable `/evidence`. This baseline is not final gateway hardening.

## Required scoped bridge setup

Docker's DOCKER-INTERNAL subnet filter also dropped legitimate off-subnet packets addressed at a router container's MAC; all six nodes were healthy but the branch gateway's FORWARD counters stayed at zero. `host_l2_transit.py --apply` creates only the group-owned `SCP_G03_L2` chain and its DOCKER-USER jump. Nine rules permit permitted lab address pairs only when input and output are the SAME one of this project's three bridges. External interfaces/destinations, NAT, global bridge sysctls and default firewall policies are unchanged. Internal network rules remain intact for other traffic. No seventh container or privileged service is added.

The helper requires host Python (standard library), Docker administrative access and the iptables backend. On Windows it locates dockerd in the `docker-desktop` WSL distro and enters its network/mount namespace; on Linux run it on the local Docker host with sudo/root. It verifies project labels, exactly three expected networks, internal/isolated mode, NAT disabled and bridge identities before applying rules. `--show` reads actual rules; `--remove` removes only this project's recognized chain/jump. Reapply after recreating networks or restarting the Docker engine. Do not disable Docker firewalling globally.

`docker-compose.yml` is formatted as JSON-compatible YAML 1.2 so existing Python can inspect it without installing a YAML parser. Compose v2 accepts this representation. `tools/configure_lab.py` rebuilds it and `.env.example` from confirmed `project.json`; neither builds nor runs Docker. Do not overwrite manual Compose edits without reviewing them first.

## Image and tooling

Dockerfile uses Ubuntu 24.04, OpenSSL 3, nginx, strongSwan/swanctl 5.9+, Python 3.12 + cryptography, tcpdump/tshark, nmap, curl and testssl.sh tag v3.2.1. Build used Internet once; runtime needs none. Package daemons are suppressed during build; entrypoint starts only baseline nginx on web-hq and idles other nodes. No swanctl/KDC daemon is launched. All analysis tools are inside the image.

The tested base digest was `sha256:fe81560990fae86dc4743202b2cb4d3df98d0bcf949173cecef15ce1127ef852`. Ubuntu tag/apt updates are not fully version locked: this is a reproducible recipe, not byte-identical image output. Actual image ID and core package revisions are in `evidence/sanitized_logs/M1_runtime_checks.json`; full package inventory remains `/opt/scp-image-packages.txt` in the image. testssl source commit is `b6a951d40a5e9d32c51c54b2ebcfaa044d3d9efa`. Use `dpkg-query -W strongswan-swanctl` for installed version: this build's `swanctl --version` attempted VICI access and failed without a daemon. The Dockerfile now checks package version >=5.9 without starting IKE, and includes standard crypto plugins.

## Rebuild and start (PowerShell example)

Requirements: WSL2/Docker Desktop (or Linux Docker Engine), Compose v2 or newer, Git and host Python for the bridge helper. Set `$scpPython` to an available interpreter as described in the root README. Never auto-reboot. Tested Compose is v5.6.1. From the example Windows checkout:

```powershell
Set-Location 'D:\SCP project\lab'
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
docker version
docker compose version
docker compose config --quiet
docker compose build gw-hq  # Shared image used by all six roles.
docker compose up -d --no-build
docker compose ps
& $scpPython .\host_l2_transit.py --apply
```

All six services must be running/healthy. If subnets overlap another local network, stop and investigate; do not silently change assigned addresses. Build Internet access is separate from runtime isolation. Never add an external runtime network just to make a lab command work.

## Live validation

From the project root, the retained runner checks the actual current network rules, routes and saved PCAP without replacing it:

```powershell
& $scpPython tools/run_m1_baseline.py --requested-by ACTUAL_REQUESTER_NAME_OR_ID
```

It records scripted execution separately from an independent member retest. Use the following commands in lab/ for manual checks:

```powershell
docker compose exec client-br bash /opt/scp/roles/verify-baseline.sh
docker compose exec gw-hq bash -lc 'ip -4 addr; ip -4 route; iptables -S; ip xfrm policy; pgrep -a charon || true'
docker compose exec gw-branch bash -lc 'ip -4 addr; ip -4 route; iptables -S; ip xfrm policy'
docker compose exec attacker ip -4 route
docker compose exec web-hq bash -lc 'ip -4 route; ss -lntp'
```

Expected marker: `SCP-M1-G03-HTTP-CLEAR`. Expected client/server: 10.3.2.10 -> 10.3.1.10:80. Expected HTTP traversal is client -> branch gateway -> WAN -> HQ gateway -> web; no NAT. Prove route with both routing tables and the WAN capture; a successful curl alone is not enough. No charon, no XFRM policy, no TCP 443 yet. Ping from client to web is permitted.

Inspect all three created networks using `docker network ls --filter label=com.docker.compose.project=scp-g03-m1` then `docker network inspect <each actual network name>`. Require Internal=true, gateway_mode_ipv4=isolated, enable_ip_masquerade=false, correct IPAM/membership and no extra network or host port. Check `host_l2_transit.py --show`: all ACCEPT rules must match the same SCP bridge in/out and permitted lab addresses only. Every node must have no default route and a default-drop output filter with embedded DNS blocked. `docker compose exec attacker ip route get 10.3.1.10` must report unreachable; attacker-to-Branch ping succeeds via gw-branch. A full attacker scan/fail-closed assessment belongs to M3 and was not run here.

Safe egress check: inspect routes and rules, then use `ip route get 192.0.2.1` inside each node (documentation-only address; this does not send packets) and require unreachable. Do not scan or probe real outside networks. Host administrators can bypass container controls; this is not a sandbox against a malicious host owner.

## Take a new real WAN capture (existing evidence is protected)

The required capture already exists and must not be overwritten casually. The first scripted capture used `tools/run_m1_baseline.py --capture --requested-by 2350906014`. The `--capture` flag refuses an existing PCAP; validation without it reuses the retained real file. The following two-terminal procedure is an alternative for a deliberately authorized new capture after archiving the previous evidence:

First terminal in lab/, use actual tester ID rather than an invented identity:

```powershell
docker compose exec -e TESTER=ACTUAL_STUDENT_ID gw-hq bash /opt/scp/roles/capture-baseline.sh
```

The script finds the interface assigned 172.16.3.10/24, refuses existing PCAP or IPsec policy, records real start time/tester/interface/filter, then runs tcpdump. In the retained run it selected eth1. Second terminal in lab/:

```powershell
docker compose exec client-br bash /opt/scp/roles/verify-baseline.sh
```

Stop the capture with Ctrl+C in the first terminal after the complete HTTP response. Required real file is `evidence/pcaps/M1_baseline_wan.pcap` in the project root. No placeholder capture is supplied. Capture filter: `host 10.3.2.10 and host 10.3.1.10 and tcp port 80`. Use `-s 0` for full payload. This filtered capture demonstrates HTTP only; it does not prove the absence of all other traffic. M3's broader IKE/ESP confidentiality capture is separate future work.

## Inspect and record evidence

```powershell
docker compose exec gw-hq tshark -r /evidence/pcaps/M1_baseline_wan.pcap -Y 'http.request or http.response' -T fields -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e tcp.stream -e http.request.method -e http.request.uri -e http.response.code
docker compose exec gw-hq tshark -r /evidence/pcaps/M1_baseline_wan.pcap -Y 'tcp contains "SCP-M1-G03-HTTP-CLEAR"' -T fields -e frame.number -e ip.src -e ip.dst -e tcp.payload
docker compose exec gw-hq tshark -r /evidence/pcaps/M1_baseline_wan.pcap -q -z follow,tcp,ascii,0
Get-FileHash ..\evidence\pcaps\M1_baseline_wan.pcap -Algorithm SHA256
```

Retained result: 10 packets, stream 0; request frame 4; HTTP 200 and marker frame 6; tcpdump reported 0 dropped packets. Full commands, outputs and hash are recorded in `evidence/sanitized_logs/M1_baseline_review.md`, M1_capture_session.txt, M1_capture_console.txt and M1_runtime_checks.json. On another capture, use its actual stream/frames. If segmentation prevents a per-packet match, inspect the reassembled stream. A header-only/empty PCAP, ping-only trace or screenshot is insufficient. No independent student test or review is implied by the scripted log.

## Stop / rebuild

```powershell
& $scpPython .\host_l2_transit.py --remove
docker compose down
# Once authorized, rebuild after reviewing file changes:
docker compose build
docker compose up -d --no-build
& $scpPython .\host_l2_transit.py --apply
```

Do not use destructive prune commands. `down` removes this Compose project's containers/networks; evidence remains on the host bind mount. Future VPN migration must deliberately replace the M1 clear forwarding rules with IPsec-policy-required fail-closed rules, supply the fixed gateway swanctl paths and test T9. Merely adding VPN on top of baseline rules is insufficient.

References: [Compose networks](https://docs.docker.com/reference/compose-file/networks/), [bridge options](https://docs.docker.com/engine/network/drivers/bridge/), [isolated gateway mode](https://docs.docker.com/engine/network/port-publishing/#gateway-modes), [DOCKER-USER policies](https://docs.docker.com/engine/network/firewall-iptables/), [testssl 3.2.1](https://github.com/testssl/testssl.sh/releases/tag/v3.2.1).
