---
title: dnsmasq refuses to start on two dhcp-host reservations for one address
slug: dnsmasq-refuses-to-start-on-a-duplicate-dhcp-host-address
source: 'measured with dnsmasq 2.91 in openwrt/rootfs:x86-64-25.12.4 (the acceptance image), 2026-10-23; re-asserted on every run by TestDnsmasqRefusesToStartOnADuplicateReservation in internal/leases/fixed_uci_test.go'
---

Two `dhcp-host` lines giving one IPv4 address to two different MACs are not a skipped or ignored entry. dnsmasq reports `duplicate dhcp-host IP address 192.168.1.150 at line 3` and exits: `dnsmasq --test` returns 1, and a real start fails the same way. On a router that is every device in the household losing DHCP as its lease expires.

OpenWrt renders each `config host` section in `/etc/config/dhcp` into one `dhcp-host=<mac>,<ip>[,<name>]` line, so two host sections with the same `ip`, from any writer (LuCI, a hand edit, curfew), produce exactly this.

This is the same failure shape as the bad hostname one (`bad DHCP host name`, `FAILED to start up`): dnsmasq is strict about `dhcp-host` and fails closed on the whole service rather than on the line. It is why curfew refuses any fixed address another host entry already holds, and never writes a pin that would duplicate one (`docs/adr/0012-...`).

Also measured in the same image, by `TestARealClientMovesToItsFixedAddressOnRenewal`: a client holding a dynamic lease that is then given a reservation at a different address moves onto the reserved address on a plain renewal (busybox `udhcpc` sent SIGUSR1), without a reboot or a link change. The client's own event log shows how: `bound 10.98.1.232`, then on renewal `nak` (dnsmasq refuses to renew an address that no longer matches the reservation for that MAC), `deconfig`, and `bound 10.98.1.150`. So the move happens at the client's T1 renewal, half the lease time, and not only when the old lease expires.
