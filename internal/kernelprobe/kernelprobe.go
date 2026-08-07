// Package kernelprobe answers "does this kernel actually behave the way the
// ticket feature assumes?", on the box in front of you, without touching
// enforcement.
//
// It exists because the assumption is not self-evidently portable. Tickets are
// nftables elements with kernel timeouts, carried across a whole-table replace
// with the time they have left, and every one of those behaviours is the
// KERNEL's rather than this program's. The test suite measures them inside the
// OpenWrt userland but on whatever kernel the container host runs, so a new
// board, a firmware bump, or a different architecture can invalidate the
// result without anything here changing. This turns "it should still work"
// into a ten second answer.
//
// It is safe to run on a live router, and that is a designed property rather
// than a hope. It works in its OWN table, creates no chain and no hook, and so
// there is no path by which a packet can be affected: an unhooked table is
// never consulted. It removes its table when it finishes, and again if it
// finds one left behind by a previous run.
package kernelprobe

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/nftables"

	"github.com/wighawag/curfew/internal/contract"
)

// TableName is deliberately NOT contract.Table. The probe writes and deletes
// tables, so pointing it at the enforcement table would turn a diagnostic into
// an outage. Guarded at run time and pinned by a test, because a rename is
// exactly the kind of change that would do this by accident.
const TableName = "curfew_probe"

const setName = "probe_macs"

// The probe's own MACs. They are never matched against anything, since there
// is no chain: they exist only to be set elements.
var (
	carriedMAC  = []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01}
	expiringMAC = []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02}
)

// Check is one measured fact.
type Check struct {
	// What the fact is, phrased so a failing line says what is now untrue.
	What string
	OK   bool
	// Detail carries the numbers, so a passing run is still evidence rather
	// than a row of ticks.
	Detail string
}

// Report is the whole run.
type Report struct {
	Kernel string
	Checks []Check
}

// OK reports whether every fact held.
func (r Report) OK() bool {
	for _, c := range r.Checks {
		if !c.OK {
			return false
		}
	}
	return len(r.Checks) > 0
}

// Failures counts the facts that did not hold.
func (r Report) Failures() int {
	n := 0
	for _, c := range r.Checks {
		if !c.OK {
			n++
		}
	}
	return n
}

// String renders the report for a terminal.
func (r Report) String() string {
	var b strings.Builder
	if r.Kernel != "" {
		fmt.Fprintf(&b, "kernel: %s\n\n", r.Kernel)
	}
	for _, c := range r.Checks {
		status := "PASS"
		if !c.OK {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "%s  %s", status, c.What)
		if c.Detail != "" {
			fmt.Fprintf(&b, " (%s)", c.Detail)
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	if r.OK() {
		b.WriteString("RESULT: every fact the ticket feature relies on holds on this kernel.\n")
	} else {
		fmt.Fprintf(&b, "RESULT: %d check(s) FAILED. Tickets cannot be trusted on this kernel.\n",
			r.Failures())
	}
	return b.String()
}

// Run measures the kernel and cleans up after itself.
//
// A returned error means the run could not be completed, which is NOT the same
// as a fact being false and must not be reported as one. A Report with a
// failing check means the kernel answered, and answered wrongly.
func Run() (Report, error) {
	if TableName == contract.Table {
		return Report{}, fmt.Errorf("refusing to run: the probe table is named %q, "+
			"which is the ENFORCEMENT table; a probe must never write there", TableName)
	}
	var r Report
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		r.Kernel = strings.TrimSpace(string(b))
	}

	conn, err := nftables.New()
	if err != nil {
		return r, fmt.Errorf("opening a netlink connection: %w", err)
	}
	// A previous run that died would otherwise fail the create below.
	dropTable(conn)
	defer dropTable(conn)

	// 1. Does this kernel accept an ether_addr set with the timeout flag? On a
	//    kernel without it, everything about tickets is impossible.
	table := conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	set := &nftables.Set{
		Table: table, Name: setName,
		KeyType: nftables.TypeEtherAddr, HasTimeout: true,
	}
	if err := conn.AddSet(set, nil); err != nil {
		return r, fmt.Errorf("declaring an ether_addr set with the timeout flag: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return r, fmt.Errorf("creating the probe table and its timeout set: %w", err)
	}
	r.add("the kernel accepts an ether_addr set with 'flags timeout'", true, "")

	// 2. An element with a timeout reports a LIVE countdown, which is what a
	//    UI renders instead of tracking a clock of its own.
	live, err := lookupSet(conn)
	if err != nil {
		return r, fmt.Errorf("reading the set back: %w", err)
	}
	if err := addElement(conn, live, carriedMAC, 30*time.Second); err != nil {
		return r, fmt.Errorf("adding an element with a 30s timeout: %w", err)
	}
	first, found := readElement(conn, carriedMAC)
	r.add("a 30s element reports a live countdown", found && first > 0 && first <= 30*time.Second,
		fmt.Sprintf("got %s", first))
	if !found {
		// Nothing below can mean anything without an element to watch.
		return r, nil
	}

	// 3. The countdown moves. Without this, 'expires' could be a constant and
	//    every check below would be measuring nothing.
	time.Sleep(2 * time.Second)
	second, _ := readElement(conn, carriedMAC)
	r.add("the countdown decreases on its own", second < first,
		fmt.Sprintf("%s then %s", first, second))

	// 4. The one that matters. A whole-table replace in a single batch,
	//    carrying the element with the time it has LEFT, which is what every
	//    reconcile tick does.
	carried := second
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	table = conn.AddTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	rebuilt := &nftables.Set{
		Table: table, Name: setName,
		KeyType: nftables.TypeEtherAddr, HasTimeout: true,
	}
	if err := conn.AddSet(rebuilt, []nftables.SetElement{
		{Key: carriedMAC, Timeout: carried},
	}); err != nil {
		return r, fmt.Errorf("rebuilding the set with the carried element: %w", err)
	}
	if err := conn.Flush(); err != nil {
		return r, fmt.Errorf("replacing the whole table in one transaction: %w", err)
	}
	r.add("a whole-table replace carrying a live element succeeds in one transaction", true, "")

	after, found := readElement(conn, carriedMAC)
	r.add("the carried element survives the replace", found, fmt.Sprintf("got %s", after))
	// A jump back UP is the dangerous direction: it means every reconcile
	// re-grants the original duration, so a ticket would never end.
	r.add("the replace does not restart the clock", found && after <= carried,
		fmt.Sprintf("%s before, %s after", carried, after))

	// 5. The kernel reclaims an expired element by itself. This is the whole
	//    reason a ticket needs no background process.
	if err := addElement(conn, rebuilt, expiringMAC, 3*time.Second); err != nil {
		return r, fmt.Errorf("adding a 3s element: %w", err)
	}
	time.Sleep(5 * time.Second)
	_, stillThere := readElement(conn, expiringMAC)
	r.add("the kernel reclaims an expired element with no process involved", !stillThere, "")

	return r, nil
}

func (r *Report) add(what string, ok bool, detail string) {
	r.Checks = append(r.Checks, Check{What: what, OK: ok, Detail: detail})
}

func addElement(conn *nftables.Conn, set *nftables.Set, key []byte, d time.Duration) error {
	if err := conn.SetAddElements(set, []nftables.SetElement{{Key: key, Timeout: d}}); err != nil {
		return err
	}
	return conn.Flush()
}

func lookupSet(conn *nftables.Conn) (*nftables.Set, error) {
	return conn.GetSetByName(&nftables.Table{
		Family: nftables.TableFamilyINet, Name: TableName,
	}, setName)
}

func readElement(conn *nftables.Conn, key []byte) (time.Duration, bool) {
	s, err := lookupSet(conn)
	if err != nil {
		return 0, false
	}
	els, err := conn.GetSetElements(s)
	if err != nil {
		return 0, false
	}
	for _, el := range els {
		if bytes.Equal(el.Key, key) {
			return el.Expires, true
		}
	}
	return 0, false
}

// Present reports whether the probe left a table behind, which should never be
// true once Run has returned.
func Present() (bool, error) {
	conn, err := nftables.New()
	if err != nil {
		return false, err
	}
	return tableExists(conn)
}

func tableExists(conn *nftables.Conn) (bool, error) {
	tables, err := conn.ListTablesOfFamily(nftables.TableFamilyINet)
	if err != nil {
		return false, err
	}
	for _, t := range tables {
		if t.Name == TableName {
			return true, nil
		}
	}
	return false, nil
}

// dropTable removes the probe's own table and nothing else. It names TableName
// and never contract.Table, so it cannot disturb enforcement even when it goes
// wrong.
func dropTable(conn *nftables.Conn) {
	present, err := tableExists(conn)
	if err != nil || !present {
		return
	}
	conn.DelTable(&nftables.Table{Family: nftables.TableFamilyINet, Name: TableName})
	_ = conn.Flush()
}
