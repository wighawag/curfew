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
	"strings"
	"sync"
	"time"

	"github.com/wighawag/curfew/internal/blockstate"
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
		loc: loc, log: log, now: time.Now}
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
	// Computed from the clock every time. Nothing here depends on having
	// observed a boundary, which is what makes a missed moment impossible.
	blocked := ps.BlockedMACs(c.now().In(c.loc))

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
