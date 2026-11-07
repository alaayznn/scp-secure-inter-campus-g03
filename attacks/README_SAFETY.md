# Lab-only safety boundary

Only the group's Docker networks are authorized: Group 03, WAN 172.16.3.0/24 and campus address space 10.3.0.0/16. The actual attached LANs are 10.3.1.0/24 and 10.3.2.0/24. Never scan, spoof, replay or capture on university/third-party networks or host external interfaces. The WAN attacker is 172.16.3.66. No rogue CA goes into a real OS or browser trust store.

M1 provides design and observed baseline evidence only. No attack implementation is included. Later weak variants must remain in attacks/mitm, attacks/downgrade or attacks/replay, isolated from final service configuration. The plaintext baseline is synthetic test content only. Do not introduce real credentials.
