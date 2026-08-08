package adguard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
)

// The AdGuard objects curfew owns, and nothing else.
//
// ADR 0010 fixes the boundary: curfew owns its own AdGuard objects exactly as
// it owns its own nftables table and never touches fw4. A household's own
// lists, exceptions, clients and login are left alone. So ownership here is a
// syntactic property curfew controls and a person can check by eye in
// AdGuard's own UI: a client curfew manages is named "curfew-<profile>", and
// the one filter list curfew manages is the one whose URL is served by
// curfew-daemon itself.
//
// user_rules is deliberately NOT used. It is where a household writes its own
// exceptions, and although comment sentinels were measured to survive both a
// set_rules round trip and AdGuard's own rewrite of the yaml, sharing one list
// between a program and a person means every curfew write has to reason about
// text it did not author. A separate subscribed list has no such problem, and
// it was measured to work: see FilterListName.

// ClientPrefix marks a client object as curfew's own.
const ClientPrefix = "curfew-"

// FilterListName is the name curfew gives the single filter list it owns.
//
// One list, subscribed by URL and served by curfew-daemon over its existing
// HTTP server. Measured on v0.107.78 in the test image, with baseline and
// controls: a fetched list DOES honour the $client= modifier; add_url fetches
// immediately and the rule took effect in 4ms; and
// POST /control/filtering/refresh re-fetched on every one of five consecutive
// calls with no rate limiting, the call itself taking 70-90ms and the rule
// change landing 1-4ms later, in BOTH directions. Without an explicit refresh
// AdGuard's own update interval is 24 hours, so the refresh is what makes a
// window boundary prompt rather than eventual.
const FilterListName = "curfew (managed: do not edit)"

// ClientName is the AdGuard client name for a profile.
//
// Non-alphanumeric characters are folded because the name is referenced from
// filter rules as `$client=<name>`, where a space or a comma would change how
// the rule parses.
func ClientName(profile string) string {
	var b strings.Builder
	b.WriteString(ClientPrefix)
	prev := false
	for _, r := range strings.ToLower(profile) {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'z') {
			b.WriteRune(r)
			prev = false
			continue
		}
		if !prev {
			b.WriteRune('-')
			prev = true
		}
	}
	return strings.TrimRight(b.String(), "-")
}

// OwnedClient reports whether curfew manages this client object.
func OwnedClient(name string) bool { return strings.HasPrefix(name, ClientPrefix) }

// ClientObject is the subset of an AdGuard client curfew sets.
//
// Only the fields curfew actually manages are listed. The rest of an AdGuard
// client (safe search, parental, upstreams) is left to whatever AdGuard
// defaults to, because setting a field curfew has no opinion about is how a
// household's deliberate choice gets silently overwritten.
type ClientObject struct {
	Name string `json:"name"`
	// IDs are the addresses this client is recognised by. AdGuard cannot key a
	// client by MAC at all (ADR 0010, measured with controls), so these are
	// the pinned IPv4 lease plus whatever IPv6 addresses the device currently
	// presents.
	IDs []string `json:"ids"`
	// BlockedServices names entries from AdGuard's BUILT-IN catalogue
	// (youtube, tiktok, netflix, roblox, discord...). It is preferred over a
	// hand-written domain list because it is maintained upstream and survives
	// the domain churn that makes a household's own list rot.
	BlockedServices []string `json:"blocked_services"`
	// UseGlobalBlockedServices must be false for BlockedServices to apply.
	UseGlobalBlockedServices bool `json:"use_global_blocked_services"`
	UseGlobalSettings        bool `json:"use_global_settings"`
	FilteringEnabled         bool `json:"filtering_enabled"`
}

// SameAs reports whether AdGuard already holds this exact object, so a
// reconcile writes only on a real difference.
//
// Order is ignored on both lists: AdGuard returns them in its own order, and
// treating that as a change would make curfew rewrite the client on every
// single pass.
func (c ClientObject) SameAs(other ClientObject) bool {
	return c.Name == other.Name &&
		sameSet(c.IDs, other.IDs) &&
		sameSet(c.BlockedServices, other.BlockedServices) &&
		c.UseGlobalBlockedServices == other.UseGlobalBlockedServices
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([]string(nil), a...)
	y := append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// Clients lists every client AdGuard holds, curfew's own and the household's.
func (c *Client) Clients() ([]ClientObject, error) {
	code, body, err := c.do(http.MethodGet, "/control/clients", nil, true)
	if err != nil {
		return nil, fmt.Errorf("listing AdGuard clients: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("listing AdGuard clients: HTTP %d: %s", code, strings.TrimSpace(string(body)))
	}
	var payload struct {
		Clients []ClientObject `json:"clients"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parsing AdGuard's client list: %w", err)
	}
	return payload.Clients, nil
}

// AddClient creates a client object.
func (c *Client) AddClient(obj ClientObject) error {
	return c.clientWrite("/control/clients/add", obj, obj.Name)
}

// UpdateClient replaces a client object.
//
// AdGuard's update takes the name to find and the whole new object, so a
// partial update is not expressible: whatever is sent IS the client
// afterwards. That is why ClientObject deliberately carries only fields curfew
// manages, and why curfew refuses to update a client it does not own.
func (c *Client) UpdateClient(obj ClientObject) error {
	body := map[string]any{"name": obj.Name, "data": obj}
	return c.clientWrite("/control/clients/update", body, obj.Name)
}

// DeleteClient removes a client object.
func (c *Client) DeleteClient(name string) error {
	return c.clientWrite("/control/clients/delete", map[string]any{"name": name}, name)
}

func (c *Client) clientWrite(path string, body any, name string) error {
	if !OwnedClient(name) {
		// A guard rather than a check on the caller. Everything routed through
		// here acts on a client object, and acting on one curfew did not
		// create would destroy a household's own settings for that device.
		return fmt.Errorf("refusing to modify AdGuard client %q: curfew only manages "+
			"clients named %s*", name, ClientPrefix)
	}
	code, resp, err := c.do(http.MethodPost, path, body, true)
	if err != nil {
		return fmt.Errorf("AdGuard %s: %w", path, err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("AdGuard %s for %q: HTTP %d: %s", path, name, code,
			strings.TrimSpace(string(resp)))
	}
	return nil
}

// FilterList is one subscribed filter list as AdGuard reports it.
type FilterList struct {
	ID         int64  `json:"id"`
	Name       string `json:"name"`
	URL        string `json:"url"`
	RulesCount int    `json:"rules_count"`
	Enabled    bool   `json:"enabled"`
}

// Filters lists AdGuard's subscribed lists.
func (c *Client) Filters() ([]FilterList, error) {
	code, body, err := c.do(http.MethodGet, "/control/filtering/status", nil, true)
	if err != nil {
		return nil, fmt.Errorf("reading AdGuard's filter status: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("reading AdGuard's filter status: HTTP %d: %s", code,
			strings.TrimSpace(string(body)))
	}
	var payload struct {
		Filters []FilterList `json:"filters"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parsing AdGuard's filter status: %w", err)
	}
	return payload.Filters, nil
}

// AddFilterURL subscribes AdGuard to a list.
//
// AdGuard validates by FETCHING, and returns 400 when the list is unreachable
// (measured, ADR 0010), so whatever serves the URL must already be up. That is
// why curfew-daemon registers its own list after its HTTP server is listening
// rather than at install time from a laptop.
func (c *Client) AddFilterURL(name, url string) error {
	code, resp, err := c.do(http.MethodPost, "/control/filtering/add_url",
		map[string]any{"name": name, "url": url, "whitelist": false}, true)
	if err != nil {
		return fmt.Errorf("subscribing AdGuard to %s: %w", url, err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("subscribing AdGuard to %s: HTTP %d: %s\n"+
			"       AdGuard validates a list by fetching it, so this usually means it "+
			"could not reach curfew-daemon at that address", url, code, strings.TrimSpace(string(resp)))
	}
	return nil
}

// RefreshFilters makes AdGuard re-fetch its subscribed lists now.
//
// This is what turns a served-list change into an applied one at a window
// boundary. Measured: it re-fetched on every consecutive call, with no rate
// limiting, and the new rules took effect within a few milliseconds of the
// fetch.
func (c *Client) RefreshFilters() error {
	code, resp, err := c.do(http.MethodPost, "/control/filtering/refresh",
		map[string]any{"whitelist": false}, true)
	if err != nil {
		return fmt.Errorf("refreshing AdGuard's filter lists: %w", err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("refreshing AdGuard's filter lists: HTTP %d: %s", code,
			strings.TrimSpace(string(resp)))
	}
	return nil
}

// Services lists AdGuard's built-in service catalogue, so a UI can offer what
// this AdGuard actually knows about rather than a list compiled into curfew
// that drifts from it.
func (c *Client) Services() ([]string, error) {
	code, body, err := c.do(http.MethodGet, "/control/blocked_services/all", nil, true)
	if err != nil {
		return nil, fmt.Errorf("reading AdGuard's service catalogue: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("reading AdGuard's service catalogue: HTTP %d", code)
	}
	var payload struct {
		BlockedServices []struct {
			ID string `json:"id"`
		} `json:"blocked_services"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, fmt.Errorf("parsing AdGuard's service catalogue: %w", err)
	}
	out := make([]string, 0, len(payload.BlockedServices))
	for _, s := range payload.BlockedServices {
		out = append(out, s.ID)
	}
	sort.Strings(out)
	return out, nil
}
