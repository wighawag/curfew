# AdGuard Home owns DNS filtering, not dnsmasq

**Status:** accepted

Global content filtering (gambling, porn, malware, phishing and similar categories) is done by AdGuard Home, which takes port 53, while dnsmasq is moved to port 54 and reduced to serving DHCP. We started with dnsmasq blocklists and hit a hard limit: **dnsmasq cannot cope with blocklists of the size these categories require**, so the filtering the household actually wants was not achievable on that path. AdGuard Home handles lists of that scale, updates them itself, and brings a query log and a UI that make it possible to see why a domain was blocked and to add an exception.

## Considered Options

- **AdGuard Home on port 53 (chosen).** Handles large lists, self-updating, inspectable, and exceptions are a first-class feature.
- **dnsmasq with downloaded blocklists (rejected, and still present in the tree).** The original approach, implemented by `blocklists.sh` writing `/etc/dnsmasq.d/blocklists.conf`. It fails on list size. Since AdGuard now owns port 53 this path no longer filters anything and is legacy.
- **Both in parallel (not chosen).** Only one process can own port 53, and splitting filtering across two engines would make "why was this blocked?" unanswerable.

## Consequences

- dnsmasq keeps DHCP duties on port 54. Anything that assumes dnsmasq answers DNS is wrong on this router.
- **AdGuard's configuration is now load-bearing state that nothing manages.** It holds user-added exceptions (for example allowing `*.eth.limo`, which the default lists block), and those were lost on a `panic-off.sh` plus reinstall cycle. AdGuard config must be brought under the same pull/push and backup story as the rest of the configuration; until it is, every reinstall silently discards hand-made exceptions.
- The recovery path (`panic-off.sh`) deliberately restores dnsmasq to port 53, which means filtering is absent while in the panic state. That is intended: panic mode restores connectivity, not policy.
- `blocklists.sh`, its weekly cron entry and its config file are dead weight to be retired.
