# Secure Inter-Campus Communication Network

Secure Communication Protocols (1305301), First Semester 2026/2027. Independent SCP workspace; no SEC files are used.

**M1 status: Designs, image build, six-node baseline and real WAN capture completed; formal acceptance items remain open. No M1 tag.** No M2 or later implementation is included. Group G3 is normalized to GROUP_ID=03 / GROUP_NUM=3. Member names and IDs are preserved exactly in `project.json` and TeamPlan. Instructor approval for the two-member team was reported; no written approval artifact is included.

Source: `SCP_Final_Project_Specification_English_2026_v1.pdf` (11 pages, v1.0). Original M1 deadline: 06/11/2026; preparation date: 07/11/2026 (Asia/Amman). No extension or modified deadline is assumed. Final assignment deadline is 25/12/2026.

## Starter Kit discrepancy

No Starter Kit was provided to the team. `lab/` and `.gitignore` are project-local replacements prepared from the specification, not official instructor files. Assignment sections 3.1 and 12 assume a provided kit and prohibit lab/ changes without written instructor approval. Acceptance of these replacements has not been established and must be clarified before claiming compliance.

## M1 documents and sources

- [M1_Submission.pdf](docs/M1/M1_Submission.pdf): one-file instructor package, including a clickable GitHub link, real baseline summary and all six required documents with PDF bookmarks.
- `docs/M1/M1_Requirements.pdf`: FR01-FR12, SR01-SR14, actors, acceptance gates and traceability.
- `docs/M1/M1_Topology_Trust.pdf`: six nodes, actual group addresses, four trust domains, baseline and target flows.
- `docs/M1/M1_PKI_Design.pdf`: offline Root/Issuing hierarchy, profiles, keys, >=3 staff certs and CRL lifecycle.
- `docs/M1/M1_ProtocolDesign.pdf`: TLS 1.3, mTLS, IKEv2 and AS/TGS/AP draft, including pending validation choices.
- `docs/M1/M1_STRIDE.pdf`: 14 lab-specific threats with likelihood, impact, control and planned checks.
- `docs/M1/M1_TeamPlan.pdf`: confirmed membership, proposed responsibilities, honest activity state and release plan.

Editable English sources: `docs/M1/source/*.md`; shared confirmed metadata: `project.json`. `tools/build_docs.py` renders them with diagrams and original Arabic member names using reportlab. Retained sources are not disposable export files. Review output visually after edits.

## Repository layout and stage boundaries

`lab/` holds Compose, Dockerfile and baseline roles; `evidence/` contains actual static checks and reserves future real evidence directories; `tools/` holds document/metadata/check generators. Required final-stage directories (`pki`, `crypto`, `tls`, `ipsec`, `auth_protocols`, `attacks`, `tests`, `contribution`, docs/M2-M4) are reserved where needed by `.gitkeep`; their future deliverable files are deliberately absent. Empty directories do not mean completed functionality. `attacks/README_SAFETY.md` defines authorization. No `swanctl.conf`, PKI issuance script, crypto implementation, TLS config or KDC implementation is supplied as M1 implementation.

## Rebuild preparation artifacts (no lab required)

Use Python with reportlab and pypdf available, and an Arabic-capable font. Set `$scpPython` to the full path of that interpreter on your machine:

```powershell
$scpPython = 'PATH_TO_YOUR_PYTHON_EXECUTABLE'
& $scpPython -X utf8 tools/configure_lab.py
& $scpPython -X utf8 tools/build_docs.py
& $scpPython -X utf8 tools/check_m1.py
& $scpPython -X utf8 tools/scan_secrets.py
```

No command above installs tools or operates Docker. `configure_lab.py` regenerates Compose/.env.example; review changes first. `build_docs.py` needs a local Arabic-capable font for original names and Poppler is used separately for visual QA. After rendering individual PDFs, use `tools/build_docs.py --submission` for the one-file package. Its editable cover is `docs/M1/source/Submission_Cover.md`. PDF review details are in the static log.

## Verified baseline and rebuild

See `lab/README.md` for build/start/stop, scoped host bridge rules and capture commands. Six services use Ubuntu 24.04: gw-hq, gw-branch, web-hq, kdc, client-br, attacker. Baseline HTTP is `http://portal.g03.scp.lab/baseline.txt`, responding `SCP-M1-G03-HTTP-CLEAR`. Networks are internal/isolated with no NAT or published host ports. `lab/host_l2_transit.py --apply` permits only lab-address traffic on the same SCP bridge before Docker's internal-subnet filter; no external interface or global default policy is changed.

Actual capture: `evidence/pcaps/M1_baseline_wan.pcap`, 10 packets / 1221 bytes, collected on gw-hq WAN `eth1` (172.16.3.10/24) at 20:37:27 UTC / 23:37:27 Asia/Amman on 07/11/2026. Frame 4 is HTTP GET; frame 6 is HTTP 200 with readable known content. SHA-256: `9d2a6dc6646d15deb81ebe6109535b3dc6d3cbb3dbfad7ccd39f3aea7c53ee9d`. The capture script discovers the interface dynamically; another rebuild may assign a different name.

`tools/run_m1_baseline.py` performs live checks and optionally takes a real capture. `--capture` refuses existing evidence; omit it to revalidate the retained PCAP. The latest run passed 44 runtime checks, including six healthy nodes, exact IPs, no default routes, output/DNS filtering, three isolated networks, scoped host transit rules, attacker reachability limits and no VPN daemon/policy. Execution is a scripted run requested by 2350906014; no independent student review/retest is claimed. Commands/results and readable TCP stream are in `evidence/sanitized_logs/M1_runtime_checks.json`; a concise review is in `M1_baseline_review.md` there.

## Remaining M1 gates

1. Clarify instructor acceptance of the locally prepared lab/, original deadline handling and Public visibility instead of the specified private repository. None is assumed approved.
2. Complete the confirmed member review/retest plan: Alaa 2350906014 leads integration; Baghdad 2300906110 reviews and independently retests. Record actual contribution only.
3. Run final document/history/secret checks after resolving the remaining gates, then create/push annotated M1 tag. No M1 tag now.

## GitHub and secrets

Public repository: [alaayznn/scp-secure-inter-campus-g03](https://github.com/alaayznn/scp-secure-inter-campus-g03), made public at the team's explicit request because the instructor's username is unknown. Anonymous reading was verified. The assignment requires private visibility, so this is a disclosed exception pending instructor acceptance. Account-free reading does not establish approval of that exception. Git 2.55.0 is used; local main tracks origin/main. No tag named M1 exists.

`.gitignore` excludes .env, private keys, p12/pfx, PSKs and key logs before the first commit; root material must also stay outside all repository mounts. Run `tools/scan_secrets.py` before commits/tags and inspect staged diffs manually. It scans current nonignored files and reachable history (including reflogs) for known credential/private-key markers and forbidden paths; it is not proof that all possible secrets are absent. No actual credentials have been created for the lab.

## Tested environment

Host: WSL 3.0.3.0, Docker Desktop 4.98.0.245422 / Engine 29.9.2, Compose v5.6.1. The manual Windows restart is complete and the Linux engine works. Lab: Ubuntu 24.04, OpenSSL 3.0.13 (Ubuntu security package), nginx 1.24.0, strongSwan 5.9.13, Python 3.12.3 + cryptography 41.0.7, tcpdump 4.99.4, tshark 4.2.2 and testssl.sh 3.2.1. Exact package revisions/image ID are recorded in the runtime log. Runtime analysis tools are inside the image; Wireshark GUI is not required for the documented tshark checks.

Python on the host is used for project generation and the scoped bridge helper (standard library only for the latter). PDF generation additionally uses reportlab/pypdf and a suitable font. Existing available tools were used; no host security-tool suite was installed. No automatic reboot was performed.

The image is cached and runtime can operate offline. Keep at least the assignment's 10 GB free disk; Windows/WSL build caches need additional space over time. Do not use destructive Docker prune commands against other projects. The initial build's swanctl version check was replaced with a package-version check so it never requires starting IKE; missing standard plugins were added. The Docker internal-routing issue and scoped fix are documented in the baseline review.

## شرح سريع بالعربي

M1 يثبت ماذا سنبني وكيف سنختبره. شبكة WAN بين الفرعين غير موثوقة؛ baseline هو قياس الاتصال قبل VPN ويجب أن يظهر HTTP مقروءًا. لاحقًا VPN يحمي بين البوابتين، وTLS يحمي اتصال العميل بالخادم، وmTLS يطلب شهادة العميل لمنطقة الموظفين. Root CA جهة تصديق جذرية معزولة، وIssuing CA جهة تصدر الشهادات. CRL قائمة الشهادات الملغاة. KDC يوزع تذاكر ومفاتيح جلسات؛ nonces قيم حديثة وتخزين الرسائل السابقة يمنع replay، أي إعادة إرسال رسالة صحيحة قديمة. STRIDE طريقة منظمة لحصر التهديدات. كل ما يخص هذه الحماية الآن تصميم فقط.

**اكتملت التصاميم وتشغيل baseline والالتقاط الحقيقي. تبقى مراجعة الفريق وقبول الاختلافات الموثقة، لذلك لم يُنشأ وسم M1.**
