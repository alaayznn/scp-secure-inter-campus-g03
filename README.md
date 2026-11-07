# Secure Inter-Campus Communication Network

Secure Communication Protocols (1305301), First Semester 2026/2027. Independent SCP workspace; no SEC files are used.

**M1 status: Design preparation completed; runtime setup in progress. Lab execution, real capture and listed gaps remain. NOT ready for submission.** No M2 or later implementation is included. Group G3 is normalized to GROUP_ID=03 / GROUP_NUM=3. Member names and IDs are preserved exactly in `project.json` and TeamPlan. Instructor approval for the two-member team was reported; no written approval artifact is included.

Source: `SCP_Final_Project_Specification_English_2026_v1.pdf` (11 pages, v1.0). Original M1 deadline: 06/11/2026; preparation date: 07/11/2026 (Asia/Amman). No extension or modified deadline is assumed. Final assignment deadline is 25/12/2026.

## Starter Kit discrepancy

No Starter Kit was provided to the team. `lab/` and `.gitignore` are project-local replacements prepared from the specification, not official instructor files. Assignment sections 3.1 and 12 assume a provided kit and prohibit lab/ changes without written instructor approval. Acceptance of these replacements has not been established and must be clarified before claiming compliance.

## M1 documents and sources

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

No command above installs tools or operates Docker. `configure_lab.py` regenerates Compose/.env.example; review changes first. `build_docs.py` needs a local Arabic-capable font for original names and Poppler is used separately for visual QA. PDF render/review details are in the static log.

## Lab preparation and deferred operation

See `lab/README.md` for image choices, route/firewall design, later build/start/stop, live checks and real capture instructions. Six services use Ubuntu 24.04; fixed names: gw-hq, gw-branch, web-hq, kdc, client-br, attacker. Baseline HTTP is `http://portal.g03.scp.lab/baseline.txt`, responding `SCP-M1-G03-HTTP-CLEAR`. No VPN autoload, IPsec policy or future-stage service should obscure it.

No Docker image was pulled/built; no lab was started and no packet capture was performed. Runtime evidence required later: `evidence/pcaps/M1_baseline_wan.pcap`. It must be genuine gw-hq WAN HTTP with readable known content and documented frame numbers. No empty/fake PCAP is created. Windows receives only runtime/Git tools as necessary later; analysis/security tools live inside the image.

## Remaining M1 gates

1. Resolve replacement-kit acceptance and original deadline handling with instructor; neither is assumed approved.
2. Carry out the confirmed planned roles: Alaa 2350906014 leads implementation; Baghdad 2300906110 reviews and independently retests. Record only actual contribution.
3. Finish the authorized Docker Desktop/WSL2 setup, confirm virtualization/Compose and available disk, build the image and record actual versions.
4. Start/verify all six nodes, isolation, routes and HTTP. Capture actual WAN baseline, inspect frames/body, record real tester/time/results/hash.
5. Complete real peer review and recheck documents/full Git history; verify instructor access using the actual username. The private repository and preparation upload are already completed.
6. Only when all mandatory gates pass, create/push annotated M1 tag. No M1 tag now.

## GitHub and secrets

Private repository: [alaayznn/scp-secure-inter-campus-g03](https://github.com/alaayznn/scp-secure-inter-campus-g03). Git 2.55.0 and existing Git authentication are used; `gh` is not required. Local main tracks origin/main. Design and baseline preparation files have been uploaded. This is a preparation upload, not a completed M1 submission. Instructor access is not yet verified (actual username needed). No tag named M1 exists.

`.gitignore` excludes .env, private keys, p12/pfx, PSKs and key logs before the first commit; root material must also stay outside all repository mounts. Run `tools/scan_secrets.py` before commits/tags and inspect staged diffs manually. It scans current nonignored files and reachable history (including reflogs) for known credential/private-key markers and forbidden paths; it is not proof that all possible secrets are absent. No actual credentials have been created for the lab.

## Tool gaps and estimates

Runtime installation was authorized on 07/11/2026. WSL 3.0.3.0 is installed and the Virtual Machine Platform feature is enabled, but Windows reports a pending restart and WSL2 cannot start yet. Firmware virtualization was confirmed enabled. Docker Desktop installation is in progress. Git, Python/reportlab/pypdf/Poppler and Bash syntax checking are available. Wireshark GUI is optional: container tshark can inspect captures. No automatic reboot will be performed.

Planning allowances only, not measured download sizes: Docker Desktop installer roughly 0.5-1 GB; WSL/kernel/distribution roughly 0.5-2 GB; Ubuntu base plus apt tools and testssl roughly 0.3-1.5 GB transferred depending on architecture/cache, with roughly 2-5 GB image/build storage. Reserve at least the assignment's 10 GB free disk; 15-20 GB allows WSL/image/cache growth. Observed free space during preparation: C: about 38.5 GB, D: about 145.5 GB. Setup time depends on downloads, virtualization and any Windows restart requirement. Automatic reboot is not permitted.

## شرح سريع بالعربي

M1 يثبت ماذا سنبني وكيف سنختبره. شبكة WAN بين الفرعين غير موثوقة؛ baseline هو قياس الاتصال قبل VPN ويجب أن يظهر HTTP مقروءًا. لاحقًا VPN يحمي بين البوابتين، وTLS يحمي اتصال العميل بالخادم، وmTLS يطلب شهادة العميل لمنطقة الموظفين. Root CA جهة تصديق جذرية معزولة، وIssuing CA جهة تصدر الشهادات. CRL قائمة الشهادات الملغاة. KDC يوزع تذاكر ومفاتيح جلسات؛ nonces قيم حديثة وتخزين الرسائل السابقة يمنع replay، أي إعادة إرسال رسالة صحيحة قديمة. STRIDE طريقة منظمة لحصر التهديدات. كل ما يخص هذه الحماية الآن تصميم فقط.

**تم تجهيز الأعمال المتاحة، ويتبقى تشغيل المختبر والالتقاط وأي نواقص مذكورة.**
