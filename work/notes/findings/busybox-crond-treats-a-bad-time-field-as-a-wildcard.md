---
title: busybox crond treats an out-of-range time field as a wildcard, not as an error
slug: busybox-crond-treats-a-bad-time-field-as-a-wildcard
source: 'measured in openwrt/rootfs:x86-64-25.12.4 (BusyBox v1.37.0), 2026-08-06, by running the real crond against real crontabs with the container clock shifted via POSIX TZ strings so that specific hour and minute boundaries could be crossed inside a 135s window.'
---

## What it does

A crontab line with an hour field of `24` does NOT fail to run, and does NOT wrap to hour 0. `crond` logs a parse error for that field and then matches the field as if it were `*`, so the job runs at **every** hour.

```
crond: user root: parse error at 24
...
crond: USER root pid 22 cmd touch /tmp/e6b/fired-hour-24
```

Measured at local hour 05, with controls that make the result unambiguous:

```
FIRED    alive        (* * * * *)   crond is running and executing
FIRED    hour-05      (* 5 * * *)   hour matching works
silent   hour-00      (* 0 * * *)   hour matching genuinely discriminates
FIRED    hour-24      (* 24 * * *)  <- the finding
FIRED    hour-99      (* 99 * * *)  <- any unparseable value, not just 24
```

The `hour-00` control is the load-bearing one. A test that only shows `* 24 * * *` firing at midnight cannot distinguish "wraps to 0" from "matches everything", and both hypotheses predict firing during a midnight window. Only running it at a non-midnight hour separates them.

Confirmed against the literal `0 <bad-hour> * * *` shape by shifting the clock to 07:58 and crossing 08:00, where the minute field still applies normally:

```
FIRED    control-every-hour-at-min-0   (0 * * * *)
silent   control-midnight-only         (0 0 * * *)
FIRED    THE-DEFECTIVE-LINE            (0 24 * * *)
```

So `0 24 * * * <cmd>` runs at the top of every hour, 24 times a day.

## Two things that do not save you

`crontab <file>` accepts the file and exits 0. There is no install-time validation, so the error only exists in the running crond's log.

The parse error goes to crond's log, which on a router is syslog. Nobody sees it.

## Why it matters here

Two jobs due in the same minute run in **file order**, measured: with `0 24 * * * block family` written above `0 8 * * * unblock family`, the block runs first and the unblock runs second, so the last action of the 08:00 minute is the unblock. The household effect of that pair is therefore not "the night block never fires", it is "the profile is blocked 23 hours a day and online from 08:00 to 09:00".

Two properties of the mechanism follow directly from the measurements above, and are recorded as facts rather than as a recommendation: a mistyped field changes a schedule's meaning rather than rejecting it, and nothing in the install or run path reports that this has happened. What to conclude from that is a design decision and belongs in an ADR once the schedule model is chosen, not here.
