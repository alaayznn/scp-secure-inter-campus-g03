# Team and Delivery Plan
Group {{GG}} | Prepared {{DATE}} | M1 only

## Confirmed membership
{{TEAM}}

Names are preserved exactly as supplied in Arabic; no official English spelling has been invented. Student IDs are used as unambiguous labels elsewhere. Instructor approval for the two-member exception is reported by the user; no written approval artifact was supplied. This does not imply approval of the replacement Starter Kit or a deadline extension.

## Confirmed planned responsibilities
The user confirmed the role allocation below. These are future responsibilities, not completed contribution claims. IDs map to the original names above.
| Workstream | Proposed owner / reviewer | Completion rule |
| Requirements, topology and document integration | 2350906014: implementation/integration. 2300906110: consistency review. IDs map to original names above. | Reviewer records actual comments/date only after reading all six PDFs and cross-checking lab addresses. |
| Baseline lab and evidence | 2350906014: operate and document. 2300906110: independently repeat HTTP and capture checks. | Actual operator/tester and commands recorded; no attribution before execution. |
| Git and release | 2350906014: prepare commits. 2300906110: review staged diff and evidence. | Both understand scope and can explain design; final tag only after all M1 gates. |
| Later milestones | Allocate after explicit user instruction. | No M2/M3 implementation begins under this M1 task. |

The user may perform most implementation. Teammate review/testing is credited only after it occurs. Each member must understand PKI, VPN, protocol and evidence for individual discussion (assignment section 14).

## Actual preparation vs planned activity
| State | Work |
| Actual | All 11 assignment pages were reviewed, the empty SCP workspace and available tools checked, and group/membership details confirmed with the reported two-member approval. |
| Actual preparation | Editable English M1 designs and baseline lab files are prepared. Document preparation is not proof of completed member review or runtime testing. Generated outputs/static results are listed in README and static review log. |
| Actual environment setup | WSL and Docker Desktop installed; official Compose configuration validation passed. Windows restart is pending. No Docker engine, image build, running lab or PCAP has been verified. |
| Planned, not performed | Teammate review, image build, six-node startup, route/isolation checks, HTTP baseline and real WAN capture. |
| Planned, not approved | Acceptance of independently authored lab/ in place of instructor kit; private repository instructor access. |
| Future, excluded | PKI issuance, crypto tool, TLS deployment, VPN, KDC implementation and attacks belong to later milestones. |

## Schedule and dependencies
Assignment dates: M1 06/11/2026; M2 20/11/2026; M3 11/12/2026; M4 25/12/2026. On preparation date 07/11/2026, M1's original deadline has passed. Confirm late-submission handling with instructor; no new date or waiver is assumed.

Next sequence: manual Windows restart -> confirm Docker engine -> build image -> verify six nodes and isolation -> prove plaintext HTTP and capture -> record actual tester/results -> peer review -> secret/history scan -> instructor access verification -> annotated M1 tag. Runtime work is authorized; the restart remains manual. This is an order of work, not a promised timetable.

## Git, branches and releases
Use one independent private SCP repository. Initial branch main; future short branches such as m1/docs and m1/baseline use small factual commits and real review. No fabricated history or teammate authorship. .gitignore precedes first commit; secrets never enter Git. Root storage stays outside repository/mounts.

Before M1: review staged paths/content, scan the full reachable Git history and current files for secret markers/forbidden paths, inspect PCAP contents for real credentials, and verify all A1-A7 gates. Scan is heuristic, supplemented by manual review. An annotated timestamped tag named M1 is created and pushed only after every mandatory item including actual runtime/PCAP is complete. No placeholder M1 tag or release now.

Connector account: alaayznn; actual remote/push status is in README. Check name uniqueness, privacy and accepted instructor access using the real username. Local-only submission needs instructor approval.

## Handover checklist
Each member should explain: why two CAs and offline Root; why at least three staff certificates for two people; what SAN/KU/EKU constrain; why VPN plus TLS; why the M1 HTTP capture must be readable; why gateway peer identity is pinned; why nonce/timestamp alone is insufficient without replay state; how fresh CRLs and failure policy work; what was actually tested and what is still planned. A review entry needs real name/ID, date, scope, findings and disposition. None is claimed here.
