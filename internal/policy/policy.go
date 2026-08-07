// Package policy is the layer that decides what the firewall SHOULD be doing,
// and owns every operation that changes it.
//
// It exists so that "block", "unblock" and "grant a ticket" are one
// implementation with one set of rules, rather than three handlers in the web
// UI that each remember to do the right things. Two of those rules are
// load-bearing and are recorded in
// docs/adr/0006-a-block-carries-a-set-of-reasons-and-manual-outranks-a-ticket.md:
//
//   - Blocking CANCELS any live ticket, here in the core, so that a later
//     unblock cannot resurrect one.
//   - Unblocking and then ticketing is a deliberate TWO-CALL gesture the
//     frontend performs. It is never fused here, so "give a grounded child 30
//     minutes" stays two visible decisions, and the ticket lapses back to the
//     schedule rather than to the block that was deliberately cleared.
//
// Desired state is computed from three inputs and nothing else: the device
// registry (who is registered), the schedule (what the clock says), and the
// persisted block state (what a parent decided). Nothing is remembered between
// ticks, so a missed moment is impossible and a reboot changes nothing except
// that tickets, which live in the kernel, are gone.
package policy

import (
	"fmt"
	"io"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/wighawag/curfew/internal/blockstate"
	"github.com/wighawag/curfew/internal/budget"
	"github.com/wighawag/curfew/internal/enforce"
	"github.com/wighawag/curfew/internal/registry"
	"github.com/wighawag/curfew/internal/schedule"
)

// Firewall is the enforcement surface this layer drives. It is an interface so
// the rules above can be tested without a kernel; internal/enforce is the only
// real implementation.
type Firewall interface {
	// EnsureApplied makes the firewall match the desired state, writing only
	// when it differs, and reports whether it wrote.
	EnsureApplied(enforce.Desired) (bool, error)
	// GrantTicket adds a kernel-timeout grant for these MACs.
	GrantTicket(macs []string, d time.Duration) error
	// CancelTickets ends any live grant for these MACs.
	CancelTickets(macs []string) error
}

// RegistryStore loads the device registry.
type RegistryStore interface {
	Load() (*registry.Registry, error)
}

// ScheduleStore loads the profiles and their windows.
type ScheduleStore interface {
	Load() (*schedule.Profiles, error)
}

// StateStore loads and saves the persisted block state.
type StateStore interface {
	Load() (*blockstate.State, error)
	Save(*blockstate.State) error
}

// Accountant is the traffic-measuring surface. It is an interface for the same
// reason Firewall is, but note what the packet-path tests do NOT do with that:
// they use the real one. A test that fakes the counter proves nothing about
// the thing most likely to be wrong.
type Accountant interface {
	// EnsureShape makes the accounting table count exactly these profiles,
	// reporting whether it rebuilt (and therefore zeroed every counter).
	EnsureShape(profiles map[string][]string) (bool, error)
	// Read returns each profile's cumulative upstream byte total.
	Read() (map[string]uint64, error)
	// Generation changes whenever the counters were reset by a rebuild.
	Generation() uint64
}

// Core is the policy layer. Use New.
type Core struct {
	// mu serialises the operations that read state, change it and write it
	// back. Two parents tapping at once is not hypothetical on a page served
	// to every phone in the house, and an interleaved read-modify-write on the
	// state file would drop one of the two decisions silently, which is the
	// only outcome this project refuses outright.
	mu       sync.Mutex
	registry RegistryStore
	schedule ScheduleStore
	state    StateStore
	firewall Firewall
	loc      *time.Location
	log      *slog.Logger
	// now is injectable so schedule-dependent behaviour can be tested at a
	// chosen moment rather than at whatever time the suite happens to run.
	now func() time.Time

	// accountant and sampler are nil when budgets are not wired up, which is
	// how the laptop-side tests and the schedule-only paths stay simple. A nil
	// accountant means usage never advances; it does NOT mean budgets are
	// ignored, because a persisted usage counter still blocks.
	accountant Accountant
	sampler    *budget.Sampler
	// observed is the last measured byte delta per profile, kept in memory for
	// the page to report. It is what makes the activity threshold calibratable
	// against the devices actually in the house rather than against a guess.
	observed map[string]budget.Observation
}

// New builds the policy layer.
func New(reg RegistryStore, sched ScheduleStore, st StateStore, fw Firewall,
	loc *time.Location, log *slog.Logger) *Core {
	if loc == nil {
		loc = time.Local
	}
	if log == nil {
		log = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return &Core{registry: reg, schedule: sched, state: st, firewall: fw,
		loc: loc, log: log, now: time.Now, observed: map[string]budget.Observation{}}
}

// WithAccounting turns budget accounting on.
//
// The interval and threshold are passed in rather than read from config here
// because they are two different kinds of knob: the threshold is household
// policy that lives with the schedule, and the interval is how often this
// process looks, which a packet-path test needs to shorten to seconds so it
// can drive a real budget to exhaustion against a real counter.
func (c *Core) WithAccounting(a Accountant, interval time.Duration, threshold uint64) *Core {
	c.accountant = a
	c.sampler = budget.NewSampler(interval, threshold)
	return c
}

// Desired computes the whole desired ruleset from config plus persisted state.
//
// It is exported because the UI compares it against what the firewall is
// actually doing, and that comparison is the project's central discipline: the
// page must be able to say "this is what should be true, and this is what the
// kernel is doing", rather than showing config back to the reader.
func (c *Core) Desired() (enforce.Desired, error) {
	reg, err := c.registry.Load()
	if err != nil {
		return enforce.Desired{}, fmt.Errorf("reading registry: %w", err)
	}
	ps, err := c.schedule.Load()
	if err != nil {
		return enforce.Desired{}, fmt.Errorf("reading schedule: %w", err)
	}
	st, err := c.state.Load()
	if err != nil {
		return enforce.Desired{}, fmt.Errorf("reading block state: %w", err)
	}
	now := c.now().In(c.loc)
	// Computed from the clock every time. Nothing here depends on having
	// observed a boundary, which is what makes a missed moment impossible.
	blocked := ps.BlockedMACs(now)

	// The budget reason, DERIVED. It is recomputed from the persisted counters
	// against the profile's limits on every single check and is never stored,
	// so it cannot latch, cannot be restored stale, and cannot be cleared by
	// anything except the usage actually falling below the allowance. It joins
	// the SAME set the schedule uses (ADR 0006's blocked_macs), so it needs no
	// new tier and is overridden by a ticket purely by chain position.
	day := st.EffectiveDay(ps.Budget.Day(now))
	inBlocked := map[string]bool{}
	for _, m := range blocked {
		inBlocked[m] = true
	}
	for _, p := range ps.Profiles {
		if p.Budget.Unlimited() {
			continue
		}
		over, _ := budget.Blocked(st.BudgetFor(p.Name, day), p.Budget, now)
		if !over {
			continue
		}
		for _, m := range p.Devices {
			m = strings.ToLower(m)
			if inBlocked[m] {
				continue
			}
			inBlocked[m] = true
			blocked = append(blocked, m)
		}
	}
	sort.Strings(blocked)

	seen := map[string]bool{}
	manual := []string{}
	for _, p := range ps.Profiles {
		if !st.IsBlocked(p.Name) {
			continue
		}
		for _, m := range p.Devices {
			m = strings.ToLower(m)
			if seen[m] {
				continue
			}
			seen[m] = true
			manual = append(manual, m)
		}
	}
	return enforce.Desired{Allowed: reg.MACs(), Blocked: blocked, Manual: manual}, nil
}

// Tick is one pass of the accounting-and-enforcement loop, and it is what the
// daemon's timer calls.
//
// It differs from Reconcile in exactly one way: it also MEASURES. That split
// matters because Reconcile is called on every button press too, and charging
// a child an interval per button press would let a parent tapping around burn
// an afternoon. Sampling is gated on real elapsed time inside the sampler as
// well, so this is belt and braces rather than a single guard.
func (c *Core) Tick() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.account(); err != nil {
		// Accounting failing must not stop enforcement: a budget that cannot be
		// measured should leave the schedule and the manual blocks running,
		// rather than taking the whole loop down with it.
		c.log.Error("budget accounting failed; enforcement continues", "error", err)
	}
	return c.reconcile()
}

// account advances every profile's budget from what the FIREWALL measured.
func (c *Core) account() error {
	if c.accountant == nil || c.sampler == nil {
		return nil
	}
	ps, err := c.schedule.Load()
	if err != nil {
		return fmt.Errorf("reading schedule: %w", err)
	}
	st, err := c.state.Load()
	if err != nil {
		return fmt.Errorf("reading block state: %w", err)
	}
	now := c.now().In(c.loc)

	// Accounting covers EVERY profile with devices, not only the budgeted
	// ones. A counter costs nothing to keep, a profile that gains a budget
	// mid-day then already has a reading to subtract from, and it is what lets
	// the page show a real idle device's byte rate so the activity threshold
	// can be calibrated against this household instead of against a guess.
	shape := make(map[string][]string, len(ps.Profiles))
	known := make(map[string]bool, len(ps.Profiles))
	for _, p := range ps.Profiles {
		known[p.Name] = true
		if len(p.Devices) > 0 {
			shape[p.Name] = p.Devices
		}
	}
	if _, err := c.accountant.EnsureShape(shape); err != nil {
		return fmt.Errorf("shaping accounting: %w", err)
	}
	counters, err := c.accountant.Read()
	if err != nil {
		return fmt.Errorf("reading counters: %w", err)
	}

	changed := false
	// The rollover, derived from the clock rather than fired at the reset
	// time. Note it can only zero budget state: it has no reach into the
	// manual blocks, so it cannot repeat the old implementation's trick of
	// silently cancelling bedtime at midnight.
	day := st.EffectiveDay(ps.Budget.Day(now))
	if st.RollOver(day) {
		c.log.Info("budget day rolled over", "day", day)
		changed = true
	}
	if st.ForgetBudget(known) {
		changed = true
	}

	obs, elapsed, ok := c.sampler.Sample(now, c.accountant.Generation(), counters)
	if ok {
		c.observed = obs
		for _, p := range ps.Profiles {
			o, seen := obs[p.Name]
			if !seen {
				// No reading this interval: the counter was reset, or the
				// profile is new. Skipping is deliberate, because the
				// alternative is crediting or charging an interval nobody
				// measured.
				continue
			}
			before := st.BudgetFor(p.Name, day)
			after := budget.Advance(before, p.Budget, now, elapsed, o.Active)
			if st.SetBudget(p.Name, after) {
				changed = true
			}
		}
	}
	if changed {
		if err := c.state.Save(st); err != nil {
			return fmt.Errorf("saving budget state: %w", err)
		}
	}
	return nil
}

// Reconcile makes the firewall match the desired state, writing only when the
// two differ.
//
// This is the level-triggered discipline the design rests on: a missed moment,
// a crash mid-write, or something else clobbering the table all self-heal on
// the next pass, instead of leaving a state nothing corrects.
func (c *Core) Reconcile() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.reconcile()
}

// reconcile is the unlocked body, so the operations below can hold the lock
// across their whole read-decide-write-enforce sequence rather than releasing
// it in the middle.
func (c *Core) reconcile() error {
	d, err := c.Desired()
	if err != nil {
		return err
	}
	if _, err := c.firewall.EnsureApplied(d); err != nil {
		return fmt.Errorf("applying ruleset: %w", err)
	}
	return nil
}

// profile finds a profile by name, or explains that it does not exist.
func (c *Core) profile(name string) (schedule.Profile, error) {
	ps, err := c.schedule.Load()
	if err != nil {
		return schedule.Profile{}, fmt.Errorf("reading schedule: %w", err)
	}
	p, ok := ps.Find(name)
	if !ok {
		return schedule.Profile{}, fmt.Errorf("no profile called %q", name)
	}
	return *p, nil
}

// Block turns the internet off for a profile until a parent turns it back on.
//
// The order of the three steps is deliberate. The decision is PERSISTED first,
// so a crash between the steps leaves a profile recorded as blocked and not
// yet enforced, which the next reconcile fixes; the reverse order would leave
// the firewall dropping packets for a decision nothing recorded, which nothing
// would ever correct. Live tickets are cancelled SECOND, before the block is
// applied, so at no instant does the profile gain access it did not have.
func (c *Core) Block(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.profile(name)
	if err != nil {
		return err
	}
	st, err := c.state.Load()
	if err != nil {
		return fmt.Errorf("reading block state: %w", err)
	}
	if st.Block(name) {
		if err := c.state.Save(st); err != nil {
			return fmt.Errorf("saving block state: %w", err)
		}
	}
	// Cancel any live ticket HERE, in the core, so that a later unblock cannot
	// resurrect one (ADR 0006). Doing it in the frontend would mean any other
	// caller of Block quietly skipped it.
	if len(p.Devices) > 0 {
		if err := c.firewall.CancelTickets(p.Devices); err != nil {
			return fmt.Errorf("cancelling tickets for %s: %w", name, err)
		}
	}
	if err := c.reconcile(); err != nil {
		return fmt.Errorf("blocked %s, but the firewall was NOT updated: %w", name, err)
	}
	c.log.Info("profile blocked", "profile", name, "devices", len(p.Devices))
	return nil
}

// Unblock lifts a parent's block, and lifts nothing else.
//
// A profile inside a bedtime window stays blocked afterwards, because the
// schedule reason is still live and this removes only the reason it owns. That
// is the single scenario on which the reason-set model and the scalar model
// were measured to differ, and the reason ADR 0006 chose the set.
func (c *Core) Unblock(name string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := c.profile(name); err != nil {
		return err
	}
	st, err := c.state.Load()
	if err != nil {
		return fmt.Errorf("reading block state: %w", err)
	}
	if st.Unblock(name) {
		if err := c.state.Save(st); err != nil {
			return fmt.Errorf("saving block state: %w", err)
		}
	}
	if err := c.reconcile(); err != nil {
		return fmt.Errorf("unblocked %s, but the firewall was NOT updated: %w", name, err)
	}
	c.log.Info("profile unblocked", "profile", name)
	return nil
}

// GrantTicket gives a profile internet access for d, overriding a schedule or
// budget block while it lasts.
//
// It REFUSES while a manual block is in force. The chain already outranks a
// ticket with a manual block, so this is not what makes a grounded child stay
// grounded; what it prevents is a ticket sitting dormant under the block and
// springing to life the moment a parent lifts it. Refusing keeps the ADR's
// two-call gesture meaningful: unblock, then ticket, as two decisions.
func (c *Core) GrantTicket(name string, d time.Duration) error {
	// Held across the manual-block check and the grant, so a block landing
	// between the two cannot leave a ticket sitting under it.
	c.mu.Lock()
	defer c.mu.Unlock()
	p, err := c.profile(name)
	if err != nil {
		return err
	}
	if len(p.Devices) == 0 {
		return fmt.Errorf("%s has no devices, so a ticket would grant nothing", name)
	}
	st, err := c.state.Load()
	if err != nil {
		return fmt.Errorf("reading block state: %w", err)
	}
	if st.IsBlocked(name) {
		return fmt.Errorf("%s is blocked until you unblock it, so a ticket would do nothing. "+
			"Unblock first if you mean to give time", name)
	}
	if err := c.firewall.GrantTicket(p.Devices, d); err != nil {
		return err
	}
	c.log.Info("ticket granted", "profile", name, "duration", d.String(),
		"devices", len(p.Devices))
	return nil
}

// BudgetStatus reports every profile's budget, keyed by profile name.
//
// The returned type lives in internal/budget, which depends on nothing, so the
// HTTP layer can render a budget without importing this package, and with it
// the ability to rewrite a firewall.
func (c *Core) BudgetStatus() (map[string]budget.Status, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	ps, err := c.schedule.Load()
	if err != nil {
		return nil, fmt.Errorf("reading schedule: %w", err)
	}
	st, err := c.state.Load()
	if err != nil {
		return nil, fmt.Errorf("reading block state: %w", err)
	}
	now := c.now().In(c.loc)
	day := st.EffectiveDay(ps.Budget.Day(now))
	out := make(map[string]budget.Status, len(ps.Profiles))
	for _, p := range ps.Profiles {
		bs := st.BudgetFor(p.Name, day)
		s := budget.Status{Limits: p.Budget, Used: bs.Usage.Std()}
		s.DailyLeft, s.DailyOK, s.SessionLeft, s.SessionOK = budget.Remaining(bs, p.Budget)
		s.Blocked, s.Reason = budget.Blocked(bs, p.Budget, now)
		if !bs.CooldownUntil.IsZero() && now.Before(bs.CooldownUntil) {
			s.CooldownLeft = bs.CooldownUntil.Sub(now)
		}
		if o, ok := c.observed[p.Name]; ok {
			s.ObservedBytes, s.ObservedOK, s.ObservedActive = o.Bytes, true, o.Active
		}
		out[p.Name] = s
	}
	return out, nil
}

// MaxTicket is the longest single ticket that can be granted.
//
// It is re-exported from internal/enforce rather than restated, so the page's
// input cap and the rule that actually refuses a grant cannot drift apart. The
// HTTP layer deliberately does not import the enforcement package at all, and
// this is how it learns the number without doing so.
func (c *Core) MaxTicket() time.Duration { return enforce.MaxTicket }

// AccountingInterval reports how long an accounting interval is, so a page can
// say what the observed byte figure is per. Zero means accounting is off.
func (c *Core) AccountingInterval() time.Duration {
	if c.sampler == nil {
		return 0
	}
	return c.sampler.Interval()
}

// ManuallyBlocked reports which profiles a parent has blocked. This is INTENT,
// read from the persisted decision; what the firewall is actually doing about
// it is read from the firewall.
func (c *Core) ManuallyBlocked() (map[string]bool, error) {
	st, err := c.state.Load()
	if err != nil {
		return nil, fmt.Errorf("reading block state: %w", err)
	}
	out := make(map[string]bool, len(st.ManualBlocked))
	for _, p := range st.ManualBlocked {
		out[p] = true
	}
	return out, nil
}
