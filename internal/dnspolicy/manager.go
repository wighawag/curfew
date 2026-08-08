package dnspolicy

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/wighawag/curfew/internal/lanhosts"
	"github.com/wighawag/curfew/internal/leases"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// Manager owns the whole DNS-refinement pass: pin the leases, observe the LAN,
// work out what AdGuard should hold, and make it so.
//
// It runs on the ROUTER, inside the daemon, for a reason worth stating. The
// device registry changes on the router's own page, so a lease pinned only
// from a laptop would leave a device added from a phone with no address, no
// AdGuard client, and a restriction that silently did not apply until somebody
// remembered to run a push.
//
// Every failure in here is REPORTED and non-fatal. Nothing in this package is
// load-bearing for whether a child is online: that is nftables on MAC, and it
// neither calls nor imports any of this. If AdGuard is unreachable, or a lease
// cannot be written, "no streaming" may not apply while bedtime and budget
// still do. Fail open on the refinement, fail closed on the control.
type Manager struct {
	registry RegistryStore
	schedule ScheduleStore
	runner   Runner
	api      API
	mem      Headroom
	listURL  string
	lan      string
	leases   string
	loc      *time.Location
	log      *slog.Logger
	now      func() time.Time

	mu sync.Mutex
	// served is the filter list text the HTTP server is handing to AdGuard
	// right now. It is held here rather than regenerated per request so that
	// what AdGuard fetches is exactly what this pass decided, even if a
	// window boundary falls between the decision and the fetch.
	served string
	// lastReport is what the most recent pass did, for the page and the log.
	lastReport Report
	// services caches AdGuard's built-in catalogue for the settings page.
	services []string
}

// RegistryStore loads the device registry.
type RegistryStore interface {
	Load() (*registry.Registry, error)
}

// ScheduleStore loads the profiles.
type ScheduleStore interface {
	Load() (*schedule.Profiles, error)
}

// Runner executes commands on the router.
type Runner interface {
	Run(cmd string) (string, error)
}

// Config is what a Manager needs to exist.
type Config struct {
	Registry RegistryStore
	Schedule ScheduleStore
	Runner   Runner
	API      API
	// Headroom decides whether the router can afford the filter-engine
	// rebuild a filter-list write causes. Nil means unmeasured, and unmeasured
	// means the write goes ahead.
	Headroom Headroom
	// ListURL is where AdGuard will fetch curfew's filter list. It must be an
	// address the ROUTER can reach, since AdGuard fetches it from there.
	ListURL string
	// LANInterface is the bridge whose neighbour table is read for IPv6.
	LANInterface string
	// LeasePath is dnsmasq's lease file, the ONLY source of IPv4 addresses.
	LeasePath string
	Location  *time.Location
	Log       *slog.Logger
}

// DefaultLeasePath is where OpenWrt's dnsmasq keeps its leases.
const DefaultLeasePath = "/tmp/dhcp.leases"

// FilterListPath is the URL path curfew-daemon serves its filter list on.
//
// It is served WITHOUT authentication, deliberately and narrowly. AdGuard
// fetches it with no credentials and has nowhere to put any, and the content
// is profile names and blocked domains only: the device addresses live in the
// AdGuard client objects, not in the list, because the rules reference the
// client by name. So there is nothing here a device on the LAN could not
// already work out, and nothing that grants access to anything.
const FilterListPath = "/curfew-filter.txt"

// NewManager builds a Manager.
func NewManager(c Config) *Manager {
	log := c.Log
	if log == nil {
		log = slog.New(slog.NewTextHandler(discard{}, nil))
	}
	loc := c.Location
	if loc == nil {
		loc = time.Local
	}
	leasePath := c.LeasePath
	if leasePath == "" {
		leasePath = DefaultLeasePath
	}
	return &Manager{
		registry: c.Registry, schedule: c.Schedule, runner: c.Runner, api: c.API, mem: c.Headroom,
		listURL: c.ListURL, lan: c.LANInterface, leases: leasePath,
		loc: loc, log: log, now: time.Now,
		// Start from something AdGuard can fetch even before the first pass,
		// so a registration that races the first tick gets a valid list rather
		// than an empty body.
		served: renderList(nil),
	}
}

// FilterList is what curfew-daemon should serve to AdGuard right now.
func (m *Manager) FilterList() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.served
}

// LastReport is what the most recent pass did.
func (m *Manager) LastReport() Report {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastReport
}

// Tick runs one pass. It is safe to call every minute: it writes only where
// the router or AdGuard disagrees with the desired state.
func (m *Manager) Tick() error {
	reg, err := m.registry.Load()
	if err != nil {
		return fmt.Errorf("reading the registry: %w", err)
	}
	ps, err := m.schedule.Load()
	if err != nil {
		return fmt.Errorf("reading the schedule: %w", err)
	}

	observed, err := lanhosts.Observe(m.runner, m.leases, m.lan)
	if err != nil {
		return err
	}

	// Pin a static lease for every registered device that currently holds an
	// address. The IPv4 half of identity becomes configuration curfew owns
	// rather than something it has to keep observing.
	//
	// A failure here is WARNED about and does not stop the pass. The AdGuard
	// half can still work from the addresses the DHCP server has already handed
	// out, and the whole layer is fail-open by design: giving up entirely would
	// turn a lease that could not be written into a restriction that silently
	// vanished, which is strictly worse than one that is applied and reported.
	plan := leases.Plan{Pinned: map[string]string{}}
	current, err := leases.Read(m.runner)
	if err != nil {
		m.log.Warn("cannot read the router's DHCP config, so no lease was pinned this pass",
			"error", err)
	} else {
		devices := make([]leases.Device, 0, len(reg.Devices))
		for _, d := range reg.Devices {
			devices = append(devices, leases.Device{
				MAC: d.MAC, Name: d.Name, IP: observed[strings.ToLower(d.MAC)].IPv4,
			})
		}
		plan = leases.Reconcile(current, devices)
		wrote, err := leases.Apply(m.runner, plan)
		if err != nil {
			m.log.Warn("could not pin static DHCP leases; the addresses already handed out "+
				"are still used for DNS restrictions", "error", err)
		} else if wrote {
			m.log.Info("static DHCP leases updated", "commands", len(plan.Commands))
		}
	}
	for _, c := range plan.Conflicts {
		m.log.Warn("a static lease curfew does not own already pins this device",
			"mac", c.MAC, "section", "dhcp."+c.Section, "ip", c.IP,
			"what_curfew_did", "left it alone and used its address")
	}
	if len(plan.Unaddressed) > 0 {
		m.log.Warn("registered devices with no DHCP lease, so no address to restrict by",
			"devices", plan.Unaddressed,
			"effect", "any DNS restriction for their profile does NOT apply to them; "+
				"schedules, budgets and manual blocks are unaffected")
	}

	desired := Compute(ps, plan.Pinned, observed, m.now().In(m.loc))

	m.mu.Lock()
	changed := desired.FilterList != m.served
	m.served = desired.FilterList
	m.mu.Unlock()

	report, err := Reconcile(m.api, desired, m.listURL, changed, m.mem)
	m.mu.Lock()
	m.lastReport = report
	m.mu.Unlock()
	if err != nil {
		return err
	}

	if report.Changed() {
		m.log.Info("AdGuard restrictions updated",
			"added", report.ClientsAdded, "updated", report.ClientsUpdated,
			"removed", report.ClientsRemoved, "list_changed", report.ListChanged,
			"list_registered", report.ListRegistered, "refreshed", report.Refreshed)
	}
	if report.Deferred != "" {
		m.log.Warn("a DNS filter change was NOT applied to AdGuard",
			"why", report.Deferred,
			"effect", "always-allowed sites and DNS restriction windows are as curfew "+
				"last managed to publish them; schedules, budgets and manual blocks are "+
				"unaffected")
	}
	if len(report.Unresolved) > 0 {
		m.log.Warn("profiles with DNS restrictions that CANNOT be applied",
			"profiles", report.Unresolved,
			"why", "none of their devices has a known address",
			"effect", "the restriction does nothing for them right now")
	}
	if len(report.PartiallyResolved) > 0 {
		m.log.Warn("profiles whose DNS restrictions apply to only SOME of their devices",
			"profiles", report.PartiallyResolved,
			"effect", "the child is restricted on one device and not another")
	}
	return nil
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// Services reports AdGuard's built-in service catalogue, cached.
//
// Cached because the settings page asks for it on every render and the answer
// changes only when AdGuard is upgraded. A failure is NOT cached: the common
// reason to fail is that AdGuard is momentarily unreachable, and remembering
// that for the life of the daemon would leave the page permanently claiming
// there are no services.
func (m *Manager) Services() ([]string, error) {
	m.mu.Lock()
	cached := m.services
	m.mu.Unlock()
	if len(cached) > 0 {
		return cached, nil
	}
	got, err := m.api.Services()
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	m.services = got
	m.mu.Unlock()
	return got, nil
}
