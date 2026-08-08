# AdGuard forwards the household's DNS in cleartext, to Google and Cloudflare

Measured on the live router, 2026-08-08, while building the per-profile DNS restrictions.

`/opt/AdGuardHome/adguardhome.yaml`:

```yaml
upstream_dns:
  - 1.1.1.1
  - 8.8.8.8
bootstrap_dns:
  - 1.1.1.1
  - 8.8.8.8
upstream_mode: load_balance
```

And the query log confirms it is not just configuration: in the last 5,000 entries, 2,198 queries went to `8.8.8.8:53` and 2,144 to `1.1.1.1:53`.

So every domain anyone in the house looks up travels **unencrypted on port 53** to a public resolver, and with `load_balance` the two providers see roughly half each. Consequences, none of which are hypothetical:

- The ISP (and anyone on the path) sees the full browsing history of the household by domain, in plaintext, including the children's.
- Google sees about half of it and Cloudflare the other half, each tied to the household's WAN address.
- The filtering itself is unaffected: this is a privacy matter, not a correctness one. AdGuard still blocks what it blocks.

There is a mild irony worth recording: curfew now blocks the well-known DoH endpoint hostnames for restricted profiles, so the children cannot use encrypted DNS, while the router itself uses none.

## The fix, and why it was not just done

AdGuard supports encrypted upstreams directly, e.g. `https://dns.cloudflare-dns.com/dns-query` or `tls://1.1.1.1`, with a plain `bootstrap_dns` to resolve the endpoint's own name once.

It was not changed, for two reasons:

1. **It is the household's setting, not curfew's.** `docs/adr/0010` draws the ownership line at curfew's own objects; upstream resolver choice is squarely a decision the household makes, and silently rerouting all its DNS through a different provider is exactly the kind of change that ADR exists to prevent.
2. **It has a real failure mode.** An encrypted upstream that cannot be reached takes DNS down for everyone, and the bootstrap ordering (resolve the endpoint name before you can use the endpoint) is a classic way to produce a resolver that works until the first restart.

If it is wanted, the shape is: change it through the REST API (`POST /control/dns_config`) rather than the yaml, verify by resolving a name through the router afterwards, and roll back to the plain upstreams if that fails, mirroring what `takeOverDNS` already does for the port-53 handover.

Choosing a provider is also a real decision rather than a detail: sending everything to one encrypted provider concentrates the same visibility that is currently split, so "encrypted" and "private" are not the same improvement.
