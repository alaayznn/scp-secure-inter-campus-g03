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
| Actual environment and baseline | WSL/Docker installed; image built; six healthy nodes and lab-only routing/isolation checked. Real WAN HTTP PCAP captured on gw-hq; frames 4/6 show request/readable response. Scripted execution requested by 2350906014; no independent member retest claimed. |
| Planned, not performed | Baghdad's independent review/retest; any individual confirmation of the scripted evidence. |
| Pending acceptance | Project-local lab/ replacement, original deadline handling, and Public repository instead of the required private visibility. No instructor approval is inferred. |
| Future, excluded | PKI issuance, crypto tool, TLS deployment, VPN, KDC implementation and attacks belong to later milestones. |

## Schedule and dependencies
Assignment dates: M1 06/11/2026; M2 20/11/2026; M3 11/12/2026; M4 25/12/2026. On preparation date 07/11/2026, M1's original deadline has passed. Confirm late-submission handling with instructor; no new date or waiver is assumed.

Completed technical sequence: environment setup -> manual restart -> image build -> six-node/isolation checks -> HTTP and actual WAN capture -> recorded frames/results. Remaining sequence: member review/retest -> instructor clarification of listed exceptions -> final secret/history review -> annotated M1 tag only after all gates pass. This is an order of work, not a new deadline.

## Git, branches and releases
Assignment requires an independent private SCP repository. The team explicitly requested Public visibility because the instructor's account is unknown; public reading is verified, but approval of that exception is pending. Branch main holds M1; future short branches use factual commits and real review. No fabricated teammate authorship or review. Secrets never enter Git; Root storage stays outside repository/mounts.

Before M1: review staged paths/content, scan the full reachable Git history and current files for secret markers/forbidden paths, inspect PCAP contents for real credentials, and verify all A1-A7 gates. Scan is heuristic, supplemented by manual review. An annotated timestamped tag named M1 is created and pushed only after every mandatory item including actual runtime/PCAP is complete. No placeholder M1 tag or release now.

Repository: https://github.com/alaayznn/scp-secure-inter-campus-g03 . It can be read without a GitHub account. Public reading solves access, not the assignment's private-repository requirement. The one-file M1_Submission.pdf includes the repository link and six required documents; it does not replace the still-pending release tag or instructor acceptance of exceptions.

## Handover checklist
Each member should explain: why two CAs and offline Root; why at least three staff certificates for two people; what SAN/KU/EKU constrain; why VPN plus TLS; why the M1 HTTP capture must be readable; why gateway peer identity is pinned; why nonce/timestamp alone is insufficient without replay state; how fresh CRLs and failure policy work; what was actually tested and what is still planned. A review entry needs real name/ID, date, scope, findings and disposition. None is claimed here.
