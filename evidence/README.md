# Evidence status

The M1 lab was built and run. `pcaps/M1_baseline_wan.pcap` is a genuine 10-packet gw-hq WAN capture with readable HTTP. `M1_baseline_review.md` in sanitized_logs records frame 4 GET and frame 6 HTTP 200/body, commands, filter, interface, date and SHA-256. No teammate review or independent member test is claimed; execution was scripted at the request of 2350906014. `.gitkeep` files preserve directories only and are not evidence.

`sanitized_logs/M1_static_review.json` records static/Compose checks and PDF review only. `M1_runtime_checks.json` separately records real container/routing/isolation/capture analysis (44 checks in the latest revalidation). `M1_host_l2_rules.json` records the scoped host rules applied to permit lab routing. `M1_environment_setup.json` records installation and post-restart state; `M1_repository_access.json` records verified Public anonymous reading and the unapproved visibility exception. `M1_secret_scan.json` is a heuristic file/history scan; manual review remains necessary before tags.

Keep the actual capture immutable unless replacing it is deliberately authorized and the original is archived. The runner refuses overwriting it. The retained stream contains synthetic marker/HTTP metadata only, with no real credential. An independent review entry must use the actual member name/ID and date, findings and disposition; none has been invented.

Future unified test log must retain section 10 fields: ID, date, tester, steps, expected, actual, PASS/FAIL, command/capture output, fix note. `test_log.xlsx` and later-stage evidence are not generated empty to suggest completion.
