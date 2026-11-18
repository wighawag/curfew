---
title: Three small gaps a review of local DNS names found and left for later
slug: local-dns-names-review-deferrals
source: 'subagent review of the local-DNS-names working tree, 2026-11-18; the P1 findings of that review were fixed before commit'
---

A reviewer found these in the local-DNS-names change. Each is real, none is a household outage, and each was left rather than squeezed into the same commit:

- **No back-off after a rollback.** A record that dnsmasq keeps rejecting (or AdGuard keeps refusing) is retried every tick, which is a commit, a reload and a rollback every minute. The ledger is now written only on a difference, and validation should keep such a record from ever being emitted, but a persistent failure still churns. A short in-memory back-off per name after a rollback would stop it.
- **AdGuard's upstream and bootstrap hostnames are not checked.** Design-notes Decision 3 asked the daemon to refuse a name covering a resolver the router uses by name. Only `system.ntp.server` is read today; the live upstreams are IP addresses, so nothing can match yet. The `Context.RouterHostnames` comment now says so.
- **The devices page does not mention a foreign dnsmasq entry for the same domain**, which `curfew push` does. The daemon still yields correctly; only the message differs between the two surfaces (story 23 asks for the same messages).
