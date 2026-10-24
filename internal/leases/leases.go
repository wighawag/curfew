// Package leases pins a registered device to an IP address by writing static
// DHCP host entries into OpenWrt's uci `dhcp` config.
//
// It exists to bridge the two identities this system uses. Enforcement is
// nftables on MAC; AdGuard's per-client DNS rules are keyed by IP and cannot
// be keyed by MAC at all (measured, with controls, in
// docs/adr/0010-curfew-drives-adguard-through-its-api-and-owns-only-its-own-objects.md:
// a client added with a MAC returns 200 OK and never matches anything, because
// AdGuard only learns MACs when it runs DHCP itself, and dnsmasq keeps DHCP
// here). Pinning the lease is what makes a device's IP something curfew's own
// configuration decides rather than something it has to observe and hope about.
//
// # What curfew owns, and what it must never touch
//
// curfew owns exactly the host sections it created, and it recognises them by
// a syntactic property it controls: a NAMED uci section whose name starts with
// "curfew_". Everything else in the file belongs to somebody else and is left
// alone, which is the same boundary curfew already keeps between its own
// nftables table and fw4.
//
// Named sections are used rather than anonymous ones for a specific reason.
// An anonymous section is addressed by INDEX (`dhcp.@host[2]`), and an index
// moves when anything before it is deleted, so a plan computed against one
// listing can act on the wrong entry when applied against another. A named
// section is addressed by a name derived from the MAC, so the same device
// always maps to the same section and convergence is idempotent by
// construction. Measured in the OpenWrt image: a named host section with an
// unknown `curfew` marker option is accepted by uci, rendered as
// `config host 'curfew_<mac>'`, and leaves a pre-existing anonymous entry
// untouched.
//
// # The entry that is already there
//
// The live router carries `dhcp.@host[0]` with mac F8:25:51:09:38:38, ip
// 192.168.1.10, name parental_printer. It was written by the shell tool this
// project replaces (config/local/device_ips names it), so it is curfew's own
// ancestry rather than a stranger's. It is deliberately NOT adopted. Adopting
// it would mean deleting an anonymous section and recreating it as a named
// one, which is a destructive rewrite of an entry in its current form, for no
// benefit: the printer is an appliance that needs no DNS refinement. Leaving
// it alone also keeps the ownership test purely syntactic, which is what makes
// "an entry curfew did not create survives" easy to keep true rather than a
// thing to remember.
package leases

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SectionPrefix marks a uci host section as curfew's own. It is the ONLY
// ownership test, deliberately: anything syntactic is checkable by a person
// reading `uci show dhcp`, where a heuristic over names or addresses is not.
const SectionPrefix = "curfew_"

// MarkerOption is written into every section curfew owns. It is redundant
// against the section name and that is the point: it makes ownership legible
// in the rendered `/etc/config/dhcp` file too, where a person looking for
// "what put this here?" will actually be reading.
const MarkerOption = "curfew"

// Host is one `config host` entry in the dhcp config.
type Host struct {
	// Section is the uci address of this entry: a name like
	// "curfew_14e01d6a9c6c", or an anonymous index like "@host[0]".
	Section string
	MAC     string
	IP      string
	Name    string
}

// Owned reports whether curfew wrote this entry and may therefore change or
// remove it. Everything else survives untouched.
func (h Host) Owned() bool { return strings.HasPrefix(h.Section, SectionPrefix) }

// SectionFor is the section name curfew uses for a MAC.
//
// It is derived from the MAC rather than from the device's name because a
// device can be renamed at any time from the router's own page, and a section
// keyed on the name would orphan the old entry and silently leave two static
// leases for one MAC.
func SectionFor(mac string) string {
	var b strings.Builder
	b.WriteString(SectionPrefix)
	for _, r := range strings.ToLower(strings.TrimSpace(mac)) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// Parse reads the output of `uci show dhcp` into the host entries it contains.
//
// It parses the SHOW output rather than the file because that is what uci
// itself reports, so anonymous sections arrive already indexed the way any
// later command would have to address them.
func Parse(uciShow string) []Host {
	type acc struct {
		mac, ip, name string
		seen          bool
	}
	order := []string{}
	bySection := map[string]*acc{}

	get := func(section string) *acc {
		a, ok := bySection[section]
		if !ok {
			a = &acc{}
			bySection[section] = a
			order = append(order, section)
		}
		return a
	}

	for _, line := range strings.Split(uciShow, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || !strings.HasPrefix(line, "dhcp.") {
			continue
		}
		key, value, hasValue := strings.Cut(line, "=")
		if !hasValue {
			continue
		}
		value = strings.Trim(value, "'\"")
		rest := strings.TrimPrefix(key, "dhcp.")

		// "dhcp.<section>=host" declares a host section.
		if !strings.Contains(rest, ".") {
			if value == "host" {
				get(rest).seen = true
			}
			continue
		}
		section, option, _ := strings.Cut(rest, ".")
		// Only record options for sections already declared as host, so an
		// option on some other section type cannot invent a host entry.
		a, ok := bySection[section]
		if !ok || !a.seen {
			continue
		}
		switch option {
		case "mac":
			a.mac = value
		case "ip":
			a.ip = value
		case "name":
			a.name = value
		}
	}

	out := make([]Host, 0, len(order))
	for _, section := range order {
		a := bySection[section]
		if !a.seen {
			continue
		}
		out = append(out, Host{Section: section, MAC: normaliseMAC(a.mac), IP: a.ip, Name: a.name})
	}
	return out
}

// normaliseMAC lowercases a MAC so entries written by hand, by LuCI or by the
// shell tool this replaces all compare equal. The live router's own entry is
// uppercase (F8:25:51:09:38:38), so this is load-bearing rather than tidy: a
// case-sensitive comparison would fail to see that MAC as already pinned and
// curfew would write a SECOND static lease for it.
func normaliseMAC(mac string) string {
	return strings.ToLower(strings.TrimSpace(mac))
}

// Device is a registered device that should be pinned.
type Device struct {
	MAC  string
	Name string
	// IP is the IPv4 address the device holds right now, from the DHCP lease
	// file. Empty means it has no lease this pass (it is off, it released, or
	// the router rebooted and /tmp/dhcp.leases is empty), which is NOT a
	// reason to drop a pin curfew already owns: see Reconcile.
	IP string
	// Fixed is the household's chosen address for the device (registry.Device
	// IP), already screened against the LAN by ScreenFixed. Empty means none.
	Fixed string
}

// Plan is what a reconcile decided to do, and why.
//
// It carries the refusals as well as the commands, because every one of them
// is a case where a per-profile DNS restriction will silently not apply to a
// device, and a feature that quietly does nothing is the failure this project
// exists to remove.
type Plan struct {
	// Commands converge the router. Empty means it already agrees, which is
	// what makes a re-run a no-op rather than a rewrite.
	Commands []string
	// Conflicts are MACs pinned by an entry curfew does not own. curfew
	// YIELDS to these: it writes no competing entry (two static leases for one
	// MAC is a broken dnsmasq config) and it removes nothing.
	Conflicts []Conflict
	// Refused are addresses curfew would have pinned and did not, because
	// another host entry or another device already has them, or because the
	// address is not valid on this LAN. Two dhcp-host lines for one address
	// stop dnsmasq starting at all (measured, dnsmasq 2.91), so a clash is
	// always a refusal and never a write.
	Refused []Refusal
	// Unaddressed are registered devices with no known IP and no pin, so
	// nothing could be pinned for them.
	Unaddressed []string
	// Pinned maps MAC to the IPv4 address curfew is confident about, INCLUDING
	// addresses owned by a foreign entry and pins kept for a device that is
	// offline. A foreign pin is still a pin, and using it costs nothing while
	// refusing to would throw away a fact.
	Pinned map[string]string
}

// Conflict is a foreign entry pinning a MAC curfew also wanted to pin.
type Conflict struct {
	MAC     string
	Section string
	IP      string
}

// Refusal is an address curfew declined to pin for a device.
type Refusal struct {
	MAC    string
	IP     string
	Reason string
}

// Reconcile works out how to make the router's host entries match the devices,
// preserving everything curfew does not own.
//
// # Which address a device is pinned at
//
// In order of precedence: its FIXED ADDRESS when the household chose one; else
// the address it holds right now; else the pin curfew already owns for it,
// kept unchanged; else nothing, and it is reported as unaddressed.
//
// The observed address is pinned rather than one allocated from a reserved
// range. That choice is made against the real lease data: all 21 registered
// devices on this household's router sat inside the DHCP pool
// (192.168.1.100-249), so a reserved block would move every one of them and,
// with a 12 hour lease, would leave the household half-migrated for up to half
// a day. Pinning what a device already has converges instantly and disturbs
// nothing; dnsmasq honours a static lease inside its own pool.
//
// # A pin survives its device being away, and that is a scar
//
// This used to delete a pin as "stale" whenever the device had no lease this
// pass. A router reboot empties /tmp/dhcp.leases and a lease also leaves it on
// expiry or release, so every pin of every device not online at that moment
// was swept, and the device was re-pinned wherever it next came back. That is
// how shyrka lost 192.168.1.150 (the service bound to it went down) and how the
// printer lost 192.168.1.10, and the live router showed 28 registered devices
// with no pin at all. A pin is now removed ONLY when its device is
// deregistered. See docs/adr/0012.
//
// # No address is ever reserved twice
//
// Measured with dnsmasq 2.91: two dhcp-host lines for one address are not a
// skipped entry, they are `duplicate dhcp-host IP address` and dnsmasq refuses
// to start, so the whole household loses DHCP. So an address another host
// entry already has (a foreign one, or another device's pin even while that
// device is offline) is refused rather than taken, and the device falls back
// to the next address in its precedence. A fixed address never displaces
// another device's pin: that would silently move the other device on its next
// renewal. Two devices given the same fixed address are both refused, rather
// than one winning by MAC order.
//
// # curfew writes NO hostname, and that is a scar rather than a preference
//
// A `config host` entry may carry a `name`, which OpenWrt renders into
// `dhcp-host=<mac>,<ip>,<name>`. dnsmasq requires that third field to be a DNS
// HOSTNAME. curfew's device names are free text typed into a web form, so
// "eli phone" and "Foxwell NT710" are ordinary, and dnsmasq's response to one
// is `bad DHCP host name at line N` followed by `FAILED to start up`. Not a
// skipped entry: it refuses to start at all, so the WHOLE HOUSEHOLD loses DHCP
// and devices stop getting addresses as their leases expire. That happened on
// the live router.
//
// The name is cosmetic here, and it is the only field that can be invalid, so
// it is simply not written. Device names live in curfew's registry and on its
// page, which is where a person reads them. A sanitised hostname would be a
// nice feature and is deliberately NOT smuggled in as part of a fix: it needs
// its own collision rules and its own tests.
//
// A device with no known address and no pin is NOT given one. Allocating from
// a reserved range would hand out an address the device does not have and
// cannot be told about until its next DHCP renewal, so the AdGuard rule keyed
// to it would match nothing while looking entirely correct.
func Reconcile(current []Host, devices []Device) Plan {
	plan := Plan{Pinned: map[string]string{}}

	foreign := map[string]Host{}
	owned := map[string]Host{}
	for _, h := range current {
		if h.MAC == "" {
			continue
		}
		if h.Owned() {
			owned[h.MAC] = h
			continue
		}
		// First foreign entry for a MAC wins; a second is somebody else's
		// problem and still not ours to resolve.
		if _, seen := foreign[h.MAC]; !seen {
			foreign[h.MAC] = h
		}
	}

	sorted := make([]Device, 0, len(devices))
	for _, d := range devices {
		d.MAC = normaliseMAC(d.MAC)
		d.IP = strings.TrimSpace(d.IP)
		d.Fixed = strings.TrimSpace(d.Fixed)
		if d.MAC != "" {
			sorted = append(sorted, d)
		}
	}
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].MAC < sorted[j].MAC })
	registered := map[string]bool{}
	for _, d := range sorted {
		registered[d.MAC] = true
	}

	// claims records who holds each address before anything moves: every
	// foreign entry, and every pin curfew owns for a device still registered.
	// A device may take an address that is unclaimed or claimed by itself.
	type claim struct{ mac, by string }
	claims := map[string]claim{}
	for _, h := range current {
		if h.MAC == "" || h.IP == "" {
			continue
		}
		if h.Owned() && !registered[h.MAC] {
			continue // about to be removed, so it holds nothing
		}
		if _, taken := claims[h.IP]; !taken {
			by := "the host entry dhcp." + h.Section
			if h.Owned() {
				by = "the pin curfew owns for " + h.MAC
			}
			claims[h.IP] = claim{mac: h.MAC, by: by}
		}
	}
	free := func(mac, ip string) (bool, string) {
		c, taken := claims[ip]
		if !taken || c.mac == mac {
			return true, ""
		}
		return false, c.by
	}
	take := func(mac, ip, by string) { claims[ip] = claim{mac: mac, by: by} }

	fixedCount := map[string]int{}
	for _, d := range sorted {
		if _, yields := foreign[d.MAC]; !yields && d.Fixed != "" {
			fixedCount[d.Fixed]++
		}
	}

	chosen := map[string]string{}
	refuse := func(mac, ip, why string) {
		plan.Refused = append(plan.Refused, Refusal{MAC: mac, IP: ip, Reason: why})
	}

	// Phase 1: fixed addresses claim first, so a device merely HOLDING
	// somebody's fixed address in the lease file cannot be pinned there.
	for _, d := range sorted {
		if _, yields := foreign[d.MAC]; yields || d.Fixed == "" {
			continue
		}
		if fixedCount[d.Fixed] > 1 {
			refuse(d.MAC, d.Fixed, fmt.Sprintf("%s is the fixed address of more than one device", d.Fixed))
			continue
		}
		if ok, by := free(d.MAC, d.Fixed); !ok {
			refuse(d.MAC, d.Fixed, fmt.Sprintf("%s is already reserved by %s", d.Fixed, by))
			continue
		}
		chosen[d.MAC] = d.Fixed
		take(d.MAC, d.Fixed, "the fixed address of "+d.MAC)
	}

	// Phase 2: everything else, observed address first, then the pin it has.
	for _, d := range sorted {
		if f, clash := foreign[d.MAC]; clash {
			// Somebody else already pins this MAC. Yield, report, and still
			// USE the address: it is a fact about where this device is, and
			// refusing to read it would only make the refinement worse.
			plan.Conflicts = append(plan.Conflicts, Conflict{MAC: d.MAC, Section: f.Section, IP: f.IP})
			if f.IP != "" {
				plan.Pinned[d.MAC] = f.IP
			}
			continue
		}
		if _, done := chosen[d.MAC]; done {
			continue
		}
		if d.IP != "" {
			if ok, by := free(d.MAC, d.IP); ok {
				chosen[d.MAC] = d.IP
				take(d.MAC, d.IP, "the pin curfew owns for "+d.MAC)
				continue
			} else if have, exists := owned[d.MAC]; !exists || have.IP != d.IP {
				refuse(d.MAC, d.IP, fmt.Sprintf("%s is held in the lease file, but already reserved by %s", d.IP, by))
			}
		}
		if have, exists := owned[d.MAC]; exists && have.IP != "" {
			chosen[d.MAC] = have.IP // claimed by this MAC already, so free
			continue
		}
		if d.IP == "" && d.Fixed == "" {
			plan.Unaddressed = append(plan.Unaddressed, d.MAC)
		}
	}

	wanted := map[string]bool{}
	for _, d := range sorted {
		ip, ok := chosen[d.MAC]
		if !ok {
			continue
		}
		section := SectionFor(d.MAC)
		wanted[section] = true
		plan.Pinned[d.MAC] = ip

		have, exists := owned[d.MAC]
		if exists && have.Section == section && have.IP == ip && have.Name == "" {
			continue // already correct: emit nothing, so a re-run is a no-op
		}
		plan.Commands = append(plan.Commands,
			fmt.Sprintf("uci set dhcp.%s=host", section),
			fmt.Sprintf("uci set dhcp.%s.mac=%s", section, shellQuote(d.MAC)),
			fmt.Sprintf("uci set dhcp.%s.ip=%s", section, shellQuote(ip)),
			fmt.Sprintf("uci set dhcp.%s.%s=1", section, MarkerOption),
			// NO name. See the comment on Reconcile: a device name is free
			// text from a web form and dnsmasq requires a DNS hostname here,
			// and it refuses to start AT ALL when it gets anything else.
			//
			// `uci -q delete` exits NON-ZERO when the option is not set
			// (measured), which would abort the chain half-done, so the
			// delete carries its own `|| true`. It is unconditional because
			// it also has to REMOVE a bad name an older curfew wrote.
			fmt.Sprintf("uci -q delete dhcp.%s.name || true", section),
		)
	}

	// Remove entries curfew owns that no longer correspond to a REGISTERED
	// device: a deregistered device must not keep a reserved address for ever.
	// A registered device that is merely offline keeps its pin (see above),
	// and one that yields to a foreign entry loses curfew's competing one.
	stale := make([]string, 0, len(owned))
	for _, h := range owned {
		if !wanted[h.Section] {
			stale = append(stale, h.Section)
		}
	}
	sort.Strings(stale)
	for _, section := range stale {
		plan.Commands = append(plan.Commands,
			fmt.Sprintf("uci -q delete dhcp.%s || true", section))
	}

	sort.Strings(plan.Unaddressed)
	sort.Slice(plan.Conflicts, func(i, j int) bool { return plan.Conflicts[i].MAC < plan.Conflicts[j].MAC })
	sort.SliceStable(plan.Refused, func(i, j int) bool { return plan.Refused[i].MAC < plan.Refused[j].MAC })
	return plan
}

// shellQuote renders a value safe to pass through a shell. Device names come
// from a web form, so they can contain anything at all.
func shellQuote(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// Runner executes commands on the router. It matches the shape internal/deploy
// already uses, so the same logic can be driven over ssh from a laptop or
// locally by the daemon.
type Runner interface {
	Run(cmd string) (string, error)
}

// Apply runs a plan and makes dnsmasq pick it up, reporting whether it changed
// anything.
//
// It commits and reloads ONLY when there was something to do. A reload on
// every tick would restart the household's DHCP service every minute, which is
// a great deal worse than the drift it would be correcting.
func Apply(r Runner, plan Plan) (bool, error) {
	if len(plan.Commands) == 0 {
		return false, nil
	}
	for _, cmd := range plan.Commands {
		if _, err := r.Run(cmd); err != nil {
			// Leave the uncommitted changes behind rather than committing a
			// half-built set: `uci revert` puts the file back exactly.
			_, _ = r.Run("uci revert dhcp")
			return false, fmt.Errorf("pinning static leases (%s): %w", cmd, err)
		}
	}
	// Keep the file as it was BEFORE committing, so a rollback can restore it
	// exactly. `uci revert` only helps before a commit, and the failure this
	// guards against is only visible after one.
	if _, err := r.Run("cp /etc/config/dhcp /tmp/dhcp.curfew-rollback"); err != nil {
		return false, fmt.Errorf("backing up the dhcp config before pinning leases: %w", err)
	}
	if _, err := r.Run("uci commit dhcp"); err != nil {
		return false, fmt.Errorf("committing static leases: %w", err)
	}
	if _, err := r.Run("/etc/init.d/dnsmasq reload"); err != nil {
		return true, rollbackDHCP(r, fmt.Errorf("reloading dnsmasq after pinning static leases: %w", err))
	}
	// VERIFY, because a dnsmasq that refuses its config does not fail the
	// reload command: it exits, and the household silently stops being able to
	// get an address as leases expire. Measured on the live router, where a
	// device name containing a space produced `bad DHCP host name` and
	// `FAILED to start up`, and nothing noticed for hours.
	if err := dnsmasqAlive(r); err != nil {
		return true, rollbackDHCP(r, err)
	}
	return true, nil
}

// dnsmasqAlive reports whether dnsmasq is actually serving, quoting its own
// reason when it is not.
func dnsmasqAlive(r Runner) error {
	for range 10 {
		out, err := r.Run("pgrep dnsmasq >/dev/null 2>&1 && echo yes || echo no")
		if err == nil && strings.TrimSpace(out) == "yes" {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	reason, _ := r.Run("logread 2>/dev/null | grep -i dnsmasq | tail -2")
	msg := "dnsmasq is NOT running after the static leases were written, " +
		"so nothing on the LAN can get a DHCP address"
	if t := strings.TrimSpace(reason); t != "" {
		msg += "\n       dnsmasq said: " + t
	}
	return errors.New(msg)
}

// rollbackDHCP puts the dhcp config back and restarts dnsmasq, so a bad pin
// costs nothing rather than costing the household its addresses.
//
// This is the same shape as the port-53 rollback in internal/deploy, and for
// the same reason: writing static leases is the only thing this package does
// that can leave a device unable to get on the network at all. A rollback that
// itself fails says so unmistakably and carries the manual fix.
func rollbackDHCP(r Runner, cause error) error {
	restore := "[ -f /tmp/dhcp.curfew-rollback ] && cp /tmp/dhcp.curfew-rollback /etc/config/dhcp"
	if _, err := r.Run(restore); err != nil {
		return fmt.Errorf("%w.\n       WORSE: restoring the previous dhcp config also failed: %v.\n"+
			"       The household may have NO DHCP. Fix by hand:\n"+
			"         uci show dhcp | grep -oE '^dhcp\\.curfew_[a-z0-9]+' | sort -u | "+
			"while read s; do uci -q delete $s; done; uci commit dhcp; /etc/init.d/dnsmasq restart",
			cause, err)
	}
	if _, err := r.Run("/etc/init.d/dnsmasq restart"); err != nil {
		return fmt.Errorf("%w.\n       WORSE: restarting dnsmasq after the rollback failed: %v.\n"+
			"       The household may have NO DHCP. Fix by hand: /etc/init.d/dnsmasq restart",
			cause, err)
	}
	if err := dnsmasqAlive(r); err != nil {
		return fmt.Errorf("%w.\n       WORSE: dnsmasq did not come back after the rollback: %v.\n"+
			"       The household has NO DHCP. Fix by hand: /etc/init.d/dnsmasq restart",
			cause, err)
	}
	return fmt.Errorf("%w.\n       The previous dhcp config has been restored and dnsmasq is "+
		"running again, so addresses still work; no lease was pinned", cause)
}

// Read lists the host entries currently on the router.
func Read(r Runner) ([]Host, error) {
	out, err := r.Run("uci show dhcp")
	if err != nil {
		return nil, fmt.Errorf("reading the dhcp config: %w", err)
	}
	return Parse(out), nil
}

// Adoption: taking over a static lease curfew did not write.
//
// This is deliberately a SEPARATE, explicit operation rather than part of
// Reconcile, and that separation is the safety property. "curfew deletes host
// entries it did not create" must never become automatic behaviour, because
// the whole leases design rests on the opposite promise. So Reconcile always
// yields to a foreign entry, and only an operator running `curfew adopt-leases`
// can hand one over, after seeing exactly what will happen to it.
//
// The motivating case is the entry the SHELL TOOL THIS PROJECT REPLACES wrote
// (mac F8:25:51:09:38:38, ip 192.168.1.10, name parental_printer), which
// config/local/device_ips still records. Left alone it makes Reconcile report
// a conflict on every pass for ever, and leaves one device pinned by a
// mechanism curfew does not own.

// Adoptable is a foreign entry that could become curfew's.
type Adoptable struct {
	// Section is the uci address of the entry as it stands, such as "@host[0]".
	Section string
	MAC     string
	// IP is kept EXACTLY as it is. Adoption changes who owns the entry, never
	// where the device lives, so nothing on the LAN moves.
	IP string
	// OldName is the name on the foreign entry, NewName the registered
	// device's name, so an operator can see the rename before agreeing to it.
	OldName string
	NewName string
}

// Adoption is what an adopt run would do.
type Adoption struct {
	Entries  []Adoptable
	Commands []string
}

// PlanAdoption works out how to take over the foreign entries whose MAC is a
// registered device. registered maps a canonical MAC to its device name.
//
// Deletes are emitted FIRST and in DESCENDING index order, and both halves of
// that matter. uci resolves `@host[N]` against the STAGED config, counting
// every section of that type, so creating curfew's own sections first could
// shift the indices and delete the wrong entry, and deleting ascending shifts
// them underneath the later deletes. Getting this wrong destroys a household's
// configuration silently, which is the exact failure this package exists to
// avoid.
//
// Everything lands in ONE uci transaction. Write-then-delete would leave a
// moment with two static leases for one MAC, which dnsmasq treats as a broken
// config; delete-then-write would risk the device losing its reservation if
// the write failed. Staging both and committing once has neither problem,
// because dnsmasq never sees the intermediate state.
func PlanAdoption(current []Host, registered map[string]string) Adoption {
	var a Adoption
	type del struct {
		section string
		index   int
	}
	var deletes []del

	for _, h := range current {
		if h.Owned() || h.MAC == "" {
			continue
		}
		name, isRegistered := registered[h.MAC]
		if !isRegistered {
			// Somebody else's entry for a device curfew knows nothing about.
			// Not ours to take, now or ever.
			continue
		}
		a.Entries = append(a.Entries, Adoptable{
			Section: h.Section, MAC: h.MAC, IP: h.IP, OldName: h.Name, NewName: name,
		})
		deletes = append(deletes, del{section: h.Section, index: anonIndex(h.Section)})
	}
	if len(a.Entries) == 0 {
		return a
	}

	sort.Slice(deletes, func(i, j int) bool { return deletes[i].index > deletes[j].index })
	for _, d := range deletes {
		// `uci -q delete` exits NON-ZERO when the thing is not set (measured),
		// which would abort the transaction half-done.
		a.Commands = append(a.Commands,
			fmt.Sprintf("uci -q delete dhcp.%s || true", d.section))
	}
	sort.Slice(a.Entries, func(i, j int) bool { return a.Entries[i].MAC < a.Entries[j].MAC })
	for _, e := range a.Entries {
		section := SectionFor(e.MAC)
		a.Commands = append(a.Commands,
			fmt.Sprintf("uci set dhcp.%s=host", section),
			fmt.Sprintf("uci set dhcp.%s.mac=%s", section, shellQuote(e.MAC)),
			fmt.Sprintf("uci set dhcp.%s.ip=%s", section, shellQuote(e.IP)),
			fmt.Sprintf("uci set dhcp.%s.%s=1", section, MarkerOption))
	}
	return a
}

// anonIndex extracts N from "@host[N]", or -1 for a named section. A named
// section is not index-addressed, so it can be deleted in any order.
func anonIndex(section string) int {
	open := strings.Index(section, "[")
	close := strings.Index(section, "]")
	if !strings.HasPrefix(section, "@") || open < 0 || close < open {
		return -1
	}
	n, err := strconv.Atoi(section[open+1 : close])
	if err != nil {
		return -1
	}
	return n
}
