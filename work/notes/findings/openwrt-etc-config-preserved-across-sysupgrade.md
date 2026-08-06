---
title: Anything under /etc/config is preserved across sysupgrade and included in the standard backup
slug: openwrt-etc-config-preserved-across-sysupgrade
source: 'inspected /lib/upgrade/keep.d/ and /etc/sysupgrade.conf in openwrt/rootfs:x86-64-25.12.4, 2026-08-06'
---

OpenWrt keeps a per-package list of paths to preserve across a firmware upgrade in `/lib/upgrade/keep.d/`. The `base-files` entry lists the whole `/etc/config/` directory:

```
$ cat /lib/upgrade/keep.d/base-files
/etc/config/
/etc/config/network
/etc/config/system
/etc/dropbear/
/etc/profile.d
```

Consequences worth knowing when choosing where a config file lives:

- A file placed under `/etc/config/` **survives `sysupgrade`** with no entry in `/etc/sysupgrade.conf` (which ships containing only commented examples). This follows directly from the keep list above.
- *(Inferred, not measured.)* It should also be **included in the standard backup** that `sysupgrade -b` and LuCI's "Backup / Flash Firmware" produce, on the basis that the backup is built from the same keep lists. A container cannot run `sysupgrade`, so this was not executed; confirm on the router before relying on it.
- *(Inferred from `sysupgrade --help`, not measured.)* `sysupgrade -k` additionally writes the installed package list to `/etc/backup/installed_packages.txt`, which would be useful for rebuilding a router from scratch.
- Other packages contribute their own keep lists (`dnsmasq`, `dropbear`, `firewall4`, `uhttpd`, `netifd`, `ppp` and others were present), so a file owned by one of those packages may already be preserved for a different reason.

This makes `/etc/config/` the cheapest possible home for a config file that should survive both a reboot and a firmware upgrade, even for a file that is not in UCI format: the preservation is path-based, not format-based.

Note the contrast with `/tmp`, which is tmpfs and is wiped on every reboot. Runtime state kept there dies with the router, which is sometimes the desired behaviour (an expiring pass) and sometimes not (a bedtime block that should still be in force after a power cut).
