# Evidence status

No lab has run. No PCAP, runtime PASS, lab screenshot, member test or teammate review is claimed. `pcaps/` intentionally contains no M1_baseline_wan.pcap until a genuine capture is taken on gw-hq's WAN interface. Empty `.gitkeep` files preserve directory structure only; they are not evidence.

`sanitized_logs/M1_static_review.json` records only executed static checks with their true scope. It does not establish Docker Compose schema acceptance, image build success, Linux routing, runtime isolation or HTTP/PCAP acceptance. `sanitized_logs/M1_secret_scan.json` records a heuristic current-file and reachable-history scan; manual review remains necessary, especially before tags.

After the authorized live baseline, create ONE concise review in `sanitized_logs/M1_baseline_review.md`: actual tester name/ID and UTC/local date, six-node state, commands and outputs, route/isolation checks, actual WAN interface and IP, tcpdump filter, HTTP request/response/body frame numbers and stream, known marker, SHA-256, expected/actual and PASS/FAIL plus fix notes. Record actual results only. Link PCAP and sanitized logs. Review PCAP for credentials before staging.

Future unified test log must retain section 10 fields: ID, date, tester, steps, expected, actual, PASS/FAIL, command/capture output, fix note. `test_log.xlsx` and later-stage evidence are not generated empty to suggest completion.
