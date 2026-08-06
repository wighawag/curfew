---
title: A CGI child inheriting stdout stalls the HTTP response; uhttpd cuts it at 60s
slug: uhttpd-cgi-timeout-and-backgrounded-children
source: 'the STALL was measured directly, with busybox httpd as a CGI stand-in and with sh command substitution, 2026-08-06. The uhttpd 60s script_timeout / 30s network_timeout figures are from OpenWrt configuration docs retrieved 2026-08-06, NOT measured against uhttpd itself. The stall mechanism is a POSIX pipe-EOF property and is not uhttpd-specific; only the timeout value is.'
---

## The timeout

uhttpd's `script_timeout` defaults to **60** and is documented as: "if the called script does not write data within the given amount of seconds, the server will terminate the request with 504 Gateway Timeout response". It is an inactivity timeout, not a total-runtime limit. `network_timeout` defaults to 30.

## The stall

A CGI script that backgrounds a long-lived child **which inherits stdout** does not complete the HTTP response when the script exits: the server keeps reading until the pipe's write end is closed, which only happens when the *child* exits.

Measured over HTTP, with a 4-second child:

```
detached child   ( (sleep 4 >/dev/null 2>&1 &) )   ->  DETACHED-hi     real 0m 0.00s
inherited child  ( sleep 4 & )                     ->  INHERITED-hi    real 0m 4.00s
```

The same trap applies to shell command substitution independently of any web server, because `$(...)` also reads until EOF on the pipe:

```
direct call (no capture)            real 0m0.015s
result=$(script-that-backgrounds)   real 0m3.024s
```

So a CGI written as `result=$(worker.sh ...)`, where `worker.sh` backgrounds a timer, blocks for the timer's full duration, and uhttpd cuts the request off at `script_timeout` with a 504 even though the work itself already succeeded.

## The fix

Detach properly so no long-lived child holds the pipe: redirect the child's stdio and put it in its own subshell, `( cmd >/dev/null 2>&1 & )`, or better, do not use a background process for timing at all. Kernel-managed expiry (nftables sets with `flags timeout`) removes the need entirely.

## Related

`/usr/sbin/httpd` from busybox-extras serves as a usable CGI stand-in for reproducing this in a test container, but a real OpenWrt rootfs ships the actual `uhttpd` binary (confirmed present at `/usr/sbin/uhttpd` on `openwrt/rootfs:x86-64-25.12.4`) and should be preferred for anything asserting on server behaviour, including the 60s cutoff which is so far taken from docs rather than measured.

Note on polarity: the fix above is OUR design recommendation, not external ground truth. It is kept here for proximity to the mechanism it addresses, but the durable decision, if one is made, belongs in `docs/adr/`.
