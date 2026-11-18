package adguard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// DNS rewrites, for local DNS names (docs/adr/0013, docs/adr/0014).
//
// Measured on v0.107.78 (work/notes/findings/adguard-rewrites-and-dnsmasq-address-records-semantics.md):
// a rewrite is exactly {domain, answer, enabled}, with NO field that could
// mark it as curfew's, so this client cannot guard ownership the way the
// client-object writes do. The caller (internal/dnspolicy) does, against the
// DNS record ledger, before calling any of these. Also measured: add accepts
// an exact duplicate and creates a second copy; delete by {domain, answer}
// removes EVERY identical copy; update is PUT, and POST is 405.

// RewriteObject is one DNS rewrite as AdGuard reports it.
type RewriteObject struct {
	Domain  string `json:"domain"`
	Answer  string `json:"answer"`
	Enabled *bool  `json:"enabled,omitempty"`
}

// Rewrites lists every rewrite AdGuard holds, curfew's and the household's.
func (c *Client) Rewrites() ([]RewriteObject, error) {
	code, body, err := c.do(http.MethodGet, "/control/rewrite/list", nil, true)
	if err != nil {
		return nil, fmt.Errorf("listing AdGuard's DNS rewrites: %w", err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("listing AdGuard's DNS rewrites: HTTP %d: %s", code, strings.TrimSpace(string(body)))
	}
	var out []RewriteObject
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("parsing AdGuard's DNS rewrites: %w", err)
	}
	return out, nil
}

// AddRewrite creates a rewrite. The answer must be an address: the special
// answers "A" and "AAAA" mean "use upstream for that type" (measured), which
// is the opposite of what a local name wants, so they are refused here.
func (c *Client) AddRewrite(domain, answer string) error {
	if err := plainAnswer(answer); err != nil {
		return err
	}
	t := true
	return c.rewriteWrite(http.MethodPost, "/control/rewrite/add",
		RewriteObject{Domain: domain, Answer: answer, Enabled: &t}, domain)
}

// DeleteRewrite removes every rewrite with exactly this domain and answer.
func (c *Client) DeleteRewrite(domain, answer string) error {
	return c.rewriteWrite(http.MethodPost, "/control/rewrite/delete",
		RewriteObject{Domain: domain, Answer: answer}, domain)
}

// UpdateRewrite replaces one rewrite in place, so a moved address never
// leaves a moment where the name falls through to upstream. enabled carries
// the rewrite's on/off state across the move, so one the household switched
// off stays off.
func (c *Client) UpdateRewrite(domain, oldAnswer, newAnswer string, enabled bool) error {
	if err := plainAnswer(newAnswer); err != nil {
		return err
	}
	return c.rewriteWrite(http.MethodPut, "/control/rewrite/update", map[string]any{
		"target": RewriteObject{Domain: domain, Answer: oldAnswer},
		"update": RewriteObject{Domain: domain, Answer: newAnswer, Enabled: &enabled},
	}, domain)
}

func plainAnswer(answer string) error {
	switch strings.ToUpper(strings.TrimSpace(answer)) {
	case "A", "AAAA", "":
		return fmt.Errorf("refusing the DNS rewrite answer %q: it is not an address, and AdGuard "+
			"reads \"A\"/\"AAAA\" as \"ask upstream\"", answer)
	}
	return nil
}

func (c *Client) rewriteWrite(method, path string, body any, domain string) error {
	code, resp, err := c.do(method, path, body, true)
	if err != nil {
		return fmt.Errorf("AdGuard %s for %s: %w", path, domain, err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("AdGuard %s for %s: HTTP %d: %s", path, domain, code, strings.TrimSpace(string(resp)))
	}
	return nil
}

// RewritesEnabled reports AdGuard's global switch for DNS rewrites.
func (c *Client) RewritesEnabled() (bool, error) {
	return c.enabledFlag("/control/rewrite/settings", "DNS rewrite settings")
}

// FilteringEnabled reports whether filtering is on globally. Measured: with it
// off, rewrites do not apply to anyone (protection being off does not matter).
func (c *Client) FilteringEnabled() (bool, error) {
	return c.enabledFlag("/control/filtering/status", "filtering status")
}

func (c *Client) enabledFlag(path, what string) (bool, error) {
	code, body, err := c.do(http.MethodGet, path, nil, true)
	if err != nil {
		return false, fmt.Errorf("reading AdGuard's %s: %w", what, err)
	}
	if code != http.StatusOK {
		return false, fmt.Errorf("reading AdGuard's %s: HTTP %d", what, code)
	}
	var p struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(body, &p); err != nil {
		return false, fmt.Errorf("parsing AdGuard's %s: %w", what, err)
	}
	return p.Enabled, nil
}
