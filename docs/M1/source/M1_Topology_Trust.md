# Topology and Trust Boundaries
Group {{GG}} | Address component G={{G}} | M1 baseline and target design

## Network view
The diagram separates four trust domains: Branch LAN, untrusted WAN, HQ LAN, and offline Root CA. Only six nodes run in Docker; CA signing is an administrative activity, not a seventh service node.

{{TOPOLOGY}}

| Network | CIDR / reserved IPAM gateway | Trust and ownership |
| WAN | 172.16.{{G}}.0/24 / .254 | Untrusted; both gateways and authorized attacker. |
| HQ LAN | 10.{{G}}.1.0/24 / .254 | HQ services; use gw-hq .1 for cross-campus routes. |
| Branch LAN | 10.{{G}}.2.0/24 / .254 | Staff client; use gw-branch .1 for HQ routes. |
| Offline CA | No lab interface/address | Encrypted Root key outside repository and every Docker bind mount. |

The .254 addresses are reserved by Docker IPAM, not campus routing. Gateway mode isolated assigns no IPv4 address to the host bridge. Endpoints delete any default route and use only explicit lab routes; gateways have no external default. Interface names are discovered by assigned IPv4, never assumed eth0. Every network is internal/isolated with masquerading and IPv6 disabled and no published host ports. Docker-host administrators remain trusted.

Docker's internal-subnet filter initially dropped routed packets before the router container received them. A project-owned DOCKER-USER chain now permits only the same input/output SCP bridge and permitted lab address pairs: campus-to-campus, and attacker-to-Branch/return. All other traffic returns to normal Docker filtering. No host default policy, global sysctl, external interface or NAT rule is changed. Apply lab/host_l2_transit.py after network creation; its read-only --show output is checked during validation.

## Six-node inventory
| Node / FQDN | Address(es) | Role / attached networks |
| gw-hq.g{{GG}}.scp.lab | 172.16.{{G}}.10; 10.{{G}}.1.1 | WAN + HQ; route baseline, future VPN endpoint. |
| gw-branch.g{{GG}}.scp.lab | 172.16.{{G}}.20; 10.{{G}}.2.1 | WAN + Branch; route baseline, future VPN endpoint. |
| web-hq.g{{GG}}.scp.lab | 10.{{G}}.1.10 | HQ; baseline HTTP, later TLS portal, CRL and service. |
| kdc.g{{GG}}.scp.lab | 10.{{G}}.1.20 | HQ; idle in M1, future KDC. |
| client-br.g{{GG}}.scp.lab | 10.{{G}}.2.10 | Branch; HTTP client, future mTLS/Kerberos client. |
| attacker.g{{GG}}.scp.lab | 172.16.{{G}}.66 | WAN only; explicit route to Branch via gw-branch, no HQ route. |

portal.g{{GG}}.scp.lab and pki.g{{GG}}.scp.lab map to 10.{{G}}.1.10. Static /etc/hosts entries supply lab resolution; no university DNS is changed. Gateway certificate names and IKE identities use these same FQDNs. Source of group identity: user-confirmed G3, normalized to 03/3.

## Permitted flows and baseline routing
| Flow | M1 baseline | Future target (design only) |
| client-br -> web-hq | TCP 80, HTTP GET /baseline.txt; known text SCP-M1-G{{GG}}-HTTP-CLEAR. ICMP for reachability. | Inner HTTPS TCP 443, protected across WAN by ESP; HTTP redirect and explicit CRL exception. |
| Branch <-> HQ | Explicit routes via the two gateways. Baseline firewall permits only client-br/web-hq TCP 80 and ICMP plus established replies. | Explicit selectors 10.{{G}}.2.0/24 <-> 10.{{G}}.1.0/24, encrypted policies required. |
| client-br -> KDC / service | Not enabled in M1. | TCP 8800 on kdc; TCP 8801 on web-hq; AEAD-protected AS/TGS/AP inside tunnel. |
| Gateway <-> gateway | No IKE daemon or VPN configuration started. | UDP 500/4500 and ESP (IP protocol 50); certificate-authenticated IKEv2. |
| attacker -> Branch | Route via gw-branch; baseline forwards attacker-source traffic to Branch for later authorized tests. | Testing foothold remains lab-only; final policy tested separately. |
| attacker -> HQ | No route on attacker; gw-hq drops non-baseline WAN flows, including routed attacker-source HQ attempts. | HQ unreachable; future T10 scan proves boundary. |
| CA -> services | No private CA material mounted. No signing now. | Offline Root -> Issuing certificate/CRL only; controlled public artifact transfer. |

web-hq and kdc have 10.{{G}}.2.0/24 via 10.{{G}}.1.1. client-br has 10.{{G}}.1.0/24 via 10.{{G}}.2.1 and WAN via gw-branch. gw-hq routes Branch via 172.16.{{G}}.20; gw-branch routes HQ via 172.16.{{G}}.10. attacker routes only Branch via 172.16.{{G}}.20. No NAT is used. Source-address spoofing by a privileged attacker is a baseline risk, not a claimed authentication control.

## Target trust decisions
VPN authenticates only pinned gateways, not every certificate signed by the CA. TLS authenticates the portal end-to-end beyond VPN termination; mTLS binds a request to a staff private-key holder, not necessarily a physical person. KDC is separately trusted for ticket/session-key issuance. Root signs only Issuing CA and its CRL; Issuing cannot create subordinate CAs (pathlen 0). CRL signature verification protects authenticity over HTTP but cannot ensure availability or freshness without nextUpdate checks.

After M3 only IKE and ESP should carry campus application traffic on WAN. ARP is normal link-layer housekeeping and is excluded from the application-confidentiality claim. LAN segments remain outside the ESP tunnel: HTTPS and protocol AEAD still matter. Final fail-closed firewall is future work; M1 deliberately permits scoped plaintext so it can be observed.

## Verified M1 baseline evidence
Actual capture: gw-hq eth1, assigned 172.16.{{G}}.10/24, on 07/11/2026 at 20:37:27 UTC (23:37:27 Asia/Amman). Route: client-br -> gw-branch -> WAN -> gw-hq -> web-hq, and return. All six nodes were healthy; no XFRM policy or charon daemon was running. Capture file: evidence/pcaps/M1_baseline_wan.pcap; 10 packets, 1221 bytes. Frame 4 is GET /baseline.txt from 10.{{G}}.2.10 to 10.{{G}}.1.10; frame 6 is HTTP 200 with SCP-M1-G{{GG}}-HTTP-CLEAR. Original campus addresses remain visible on WAN; no NAT or VPN is masking them.

The filter was host 10.{{G}}.2.10 and host 10.{{G}}.1.10 and tcp port 80. The current interface name is an observation, not a hard-coded assumption for another rebuild. Commands, exact hash, stream and checks are retained in evidence/sanitized_logs/M1_capture_session.txt, M1_runtime_checks.json and M1_baseline_review.md. Independent teammate review is not claimed.
