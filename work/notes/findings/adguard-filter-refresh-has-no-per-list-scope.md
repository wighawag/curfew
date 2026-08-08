---
title: AdGuard's filter refresh has no per-list scope, but set_url toggling re-fetches exactly one list
slug: adguard-filter-refresh-has-no-per-list-scope
source: 'read AdGuardHome v0.107.78 internal/filtering/{http.go,filter.go}; measured on the live router 2026-08-08 (logread, /proc) and against the real AdGuard in the acceptance image'
---

`POST /control/filtering/refresh` re-fetches **every** subscribed blocklist. Its handler calls `tryRefreshFilters(!req.White, req.White, true)`, and the request body carries only `whitelist: bool`. There is no way to name a list. So a tool that publishes its own small list and calls refresh to make it land is paying for a re-download and re-parse of everything the household subscribes to.

On the live router that cost the household its DNS. Saving two always-allowed sites at 13:16:07 changed curfew's own 63-byte list, which called refresh, which re-fetched all eight subscribed lists (108 MB, one of them 58 MB) and rebuilt AdGuard's filtering engine. AdGuard reached 876 MB anon-rss on a 1010 MB box with no swap, `oom-kill` took it at 13:17:01, procd respawned it at 13:17:07, and `dnsproxy` did not bind :53 again until 13:17:50. Every device on the LAN was without a resolver for about 88 seconds, which presents to a person as "Server Not Found" in the browser and outlives the outage because Firefox caches the failure.

The single-list path that does exist, read from the source rather than guessed:

- `handleFilteringAddURL` calls `d.update(&filt)` on the new filter alone, then `EnableFilters(true)`. One download, one engine rebuild.
- `handleFilteringSetURL` calls `filterSetProperties`, which sets `shouldRestart` when `Enabled` changes and then, on the way back to enabled, `return d.update(flt)`. So **disable then re-enable re-fetches that one list**.
- `updateIntl` issues a plain unconditional `GET` (no `If-Modified-Since`, no ETag) and rewrites the filter's file, so the content really is re-fetched rather than replayed from AdGuard's copy.
- `handleFilteringRemoveURL` renames the file to `.old` and rebuilds; it never downloads.

Two consequences for anything driving AdGuard from outside:

1. To publish a change to your own list, toggle it off and on through `set_url`. It costs two engine rebuilds instead of one, but no other list is touched. Note the failure mode: die between the two calls and your list is left **disabled**, and nothing else will ever switch it back on, so the reconciler has to treat "my list, registered but disabled" as work to do.
2. The engine rebuild itself is unavoidable and holds the old and new engines at once, so its cost is roughly a second copy of what AdGuard already has resident. On a router with 108 MB of blocklists that is several hundred megabytes, which is why the affordability question is worth asking of `/proc` before the write rather than discovering the answer from the OOM killer.

Also worth knowing: these calls answer only after the download and the rebuild are done, so an HTTP client timeout of 10 s reports a failure for an operation that is still running and goes on to succeed.
