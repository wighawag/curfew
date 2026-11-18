package dnspolicy

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/wighawag/curfew/internal/dnsledger"
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
	rewrites RewriteAPI
	mem      Headroom
	listURL  string
	lan      string
	leases   string
	ledger   string
	loc      *time.Location
	log      *slog.Logger
	now      func() time.Time

	mu sync.Mutex
	// adguardEdit is held while something edits AdGuard's config FILE with
	// AdGuard stopped and restarted around it (a category change). Rewrite
	// reconciliation skips while it is held: a rewrite deleted through the
	// API in that window could come back from the file's backup on a
	// rollback, and would then count as the household's for ever.
	adguardEdit sync.Mutex
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
	// Rewrites is AdGuard's DNS rewrite API, for local DNS names. Nil (or no
	// LedgerPath) means AdGuard does not answer them; dnsmasq still does.
	Rewrites RewriteAPI
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
	// LedgerPath is the DNS record ledger for local DNS names
	// (internal/dnsledger). Empty means local names are not managed.
	LedgerPath string
	Location   *time.Location
	Log        *slog.Logger
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
		rewrites: c.Rewrites,
		listURL:  c.ListURL, lan: c.LANInterface, leases: leasePath, ledger: c.LedgerPath,
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

	// Pin a static lease for every registered device: at its fixed address if
	// it has one, else at the address it holds, else at the pin it already
	// has. The IPv4 half of identity becomes configuration curfew owns rather
	// than something it has to keep observing.
	//
	// A failure here is WARNED about and does not stop the pass. The AdGuard
	// half can still work from the addresses the DHCP server has already handed
	// out, and the whole layer is fail-open by design: giving up entirely would
	// turn a lease that could not be written into a restriction that silently
	// vanished, which is strictly worse than one that is applied and reported.
	devices := make([]leases.Device, 0, len(reg.Devices))
	for _, d := range reg.Devices {
		devices = append(devices, leases.Device{
			MAC: d.MAC, Name: d.Name, IP: observed[strings.ToLower(d.MAC)].IPv4, Fixed: d.IP,
			DNSNames: d.DNSNames,
		})
	}
	plan := leases.PassAndLog(m.runner, m.log, devices, leases.PassOptions{LedgerPath: m.ledger})
	if len(plan.Unaddressed) > 0 {
		m.log.Warn("registered devices with no DHCP lease, so no address to restrict by",
			"devices", plan.Unaddressed,
			"effect", "any DNS restriction for their profile does NOT apply to them; "+
				"schedules, budgets and manual blocks are unaffected")
	}

	m.reconcileRewrites(plan)

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

// DuringAdGuardEdit runs f, which edits AdGuard's config file with AdGuard
// stopped, with rewrite reconciliation held off for its whole duration
// (rollback included). It waits for a reconciliation already in flight.
func (m *Manager) DuringAdGuardEdit(f func()) {
	m.adguardEdit.Lock()
	defer m.adguardEdit.Unlock()
	f()
}

// reconcileRewrites is the AdGuard half of local DNS names. Fail-open like
// everything else here: an AdGuard error is logged and the pass goes on.
func (m *Manager) reconcileRewrites(plan leases.Plan) {
	if m.rewrites == nil || m.ledger == "" {
		return
	}
	if !m.adguardEdit.TryLock() {
		m.log.Info("local DNS names were not checked in AdGuard this pass: its config is " +
			"being changed from the settings page; the next pass does it")
		return
	}
	defer m.adguardEdit.Unlock()
	if plan.NamesSkipped != "" {
		// Ownership is unknown (an unreadable ledger), so AdGuard is left
		// exactly as it is; the DHCP pass has already said why.
		return
	}
	ledger, err := dnsledger.Load(m.ledger)
	if err != nil {
		m.log.Warn("local DNS names were not applied to AdGuard", "why", err.Error())
		return
	}
	save := func(rs []dnsledger.Rewrite) error {
		l, err := dnsledger.Load(m.ledger)
		if err != nil {
			return err
		}
		l.AdGuard = rs
		return dnsledger.Save(m.ledger, l)
	}
	rep, err := ReconcileRewrites(m.rewrites, plan.Names.Targets, ledger, save)
	if err != nil {
		m.log.Warn("local DNS names could not all be applied to AdGuard", "error", err.Error(),
			"effect", "dnsmasq still answers them after panic-off; the next pass retries")
	}
	// Saved only on a difference: the ledger lives on flash.
	if (rep.Final != nil || err == nil) && !sameRewrites(ledger.AdGuard, rep.Final) {
		if serr := save(rep.Final); serr != nil {
			m.log.Warn("could not update the DNS record ledger after writing to AdGuard "+
				"(it still lists everything curfew may own, so nothing is orphaned)", "error", serr.Error())
		}
	}
	if rep.Changed() {
		m.log.Info("AdGuard local DNS names updated", "added", rep.Added, "updated", rep.Updated,
			"removed", rep.Removed)
	}
	for _, y := range rep.Yielded {
		m.log.Warn("a local DNS name is NOT answered by AdGuard", "name", y,
			"what_curfew_did", "left the household's rewrite alone and added none")
	}
	for _, u := range rep.Unclaimed {
		m.log.Info("an AdGuard rewrite identical to curfew's was not written by curfew", "rewrite", u,
			"what_curfew_did", "left it and did not claim it; the name still resolves")
	}
	for _, k := range rep.Kept {
		m.log.Warn("an AdGuard rewrite curfew no longer wants is duplicated by one it did not create",
			"rewrite", k, "what_curfew_did", "deleted nothing, since AdGuard deletes every copy at once")
	}
	for _, d := range rep.Disabled {
		m.log.Warn("a local DNS name's AdGuard rewrite is switched off, so AdGuard does not answer it",
			"rewrite", d, "what_curfew_did", "left it as it is; dnsmasq still answers the name after panic-off")
	}
	for _, b := range rep.Bypass {
		m.log.Warn("some devices get no answer for local DNS names from AdGuard", "why", b)
	}
}

func sameRewrites(a, b []dnsledger.Rewrite) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]dnsledger.Rewrite(nil), a...)
	y := append([]dnsledger.Rewrite(nil), b...)
	sortRewrites(x)
	sortRewrites(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
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
