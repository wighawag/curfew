// Package adguard talks to AdGuard Home, which owns DNS filtering for the
// household per docs/adr/0002-adguard-home-owns-dns-filtering.md.
//
// The governing rule, decided in
// docs/adr/0010-curfew-drives-adguard-through-its-api-and-owns-only-its-own-objects.md
// and forced by measurement: **curfew does not own AdGuardHome.yaml.**
//
// AdGuard is itself an authoritative writer of that file. Measured on
// v0.107.78: a 470-byte config written at schema_version 28 came back as 3673
// bytes at 34, and an unknown top-level key we added was silently dropped on
// the next write. Two writers over one file is the "which of these owns this?"
// question ADR 0007 blames for every bug in the investigation, and it is why
// hand-made exceptions kept vanishing on a reinstall.
//
// So everything curfew changes goes through the REST API, with exactly ONE
// exception, which is unavoidable: creating the first admin user. AdGuard
// 0.107 has no API for that, so it is a single surgical line edit that
// replaces an EMPTY users list and touches nothing else. That edit refuses to
// run when a user already exists, so a household's own login is never
// disturbed.
package adguard

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// DefaultUser is the admin account curfew creates when AdGuard has none.
const DefaultUser = "parent"

// DefaultPort is AdGuard's admin/API port.
const DefaultPort = 3000

// ConfigPath is where the installer puts AdGuard's config on the router.
const ConfigPath = "/opt/AdGuardHome/adguardhome.yaml"

// BinaryPath is where the installer puts the AdGuard binary.
const BinaryPath = "/opt/AdGuardHome/AdGuardHome"

// HashPassword produces the bcrypt hash AdGuard stores.
//
// AdGuard will not accept a plaintext password in its config, and it has no
// endpoint to set one, so curfew has to hash it the same way AdGuard's own
// setup wizard does.
func HashPassword(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", errors.New("an AdGuard admin password may not be empty: " +
			"an empty one leaves the API open to every device on the LAN")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("hashing the AdGuard password: %w", err)
	}
	return string(h), nil
}

// UsersState says what an AdGuard config currently has by way of admin
// accounts.
type UsersState int

const (
	// UsersUnknown means the config has no users key we recognise, so nothing
	// should be edited: a guess here could corrupt a working install.
	UsersUnknown UsersState = iota
	// UsersEmpty is the dangerous one. It is what legacy/scripts/setup-adguard.sh
	// writes, and it means AdGuard serves its whole REST API with NO
	// authentication: measured, an unauthenticated POST /control/protection
	// {"enabled":false} returns 200 OK and turns off all filtering. The child
	// being filtered can switch off the filter.
	UsersEmpty
	// UsersPresent means somebody already has a login, which curfew leaves
	// strictly alone.
	UsersPresent
)

func (u UsersState) String() string {
	switch u {
	case UsersEmpty:
		return "no admin account (API is unauthenticated)"
	case UsersPresent:
		return "an admin account exists"
	default:
		return "unrecognised users setting"
	}
}

// InspectUsers reports whether an AdGuard config has an admin account.
//
// It reads the file textually rather than parsing the YAML, deliberately.
// Parsing and re-serialising would mean re-writing a document AdGuard owns,
// and any field a parser did not understand would be dropped on the way back
// out, which is exactly the failure this package exists to avoid.
func InspectUsers(config []byte) UsersState {
	lines := strings.Split(string(config), "\n")
	for i, line := range lines {
		trimmed := strings.TrimRight(line, " \t\r")
		// Only a TOP-LEVEL users key counts. An indented "users:" belongs to
		// some other section and must not be mistaken for this one.
		if trimmed == "users: []" {
			return UsersEmpty
		}
		if trimmed != "users:" {
			continue
		}
		// A bare "users:" is empty unless a list item follows it.
		for _, next := range lines[i+1:] {
			t := strings.TrimSpace(next)
			if t == "" || strings.HasPrefix(t, "#") {
				continue
			}
			if strings.HasPrefix(t, "-") {
				return UsersPresent
			}
			// Anything else at this point is the next key, so the list is empty.
			return UsersEmpty
		}
		return UsersEmpty
	}
	return UsersUnknown
}

// EnsureUser adds an admin account to a config that has none.
//
// It reports whether it changed anything. It refuses, without error, when an
// account already exists: adopting somebody's existing AdGuard must never
// disturb their login. It DOES error when it cannot find a users key at all,
// because silently appending to a file we do not understand is how a working
// install gets corrupted.
//
// The edit is one line. Everything else in the file, including hand-made
// exceptions and any setting AdGuard added itself, is untouched: measured, an
// `@@||eth.limo^` exception survives this edit and AdGuard's own subsequent
// rewrite, and the resulting server answers 401 unauthenticated, 200 with the
// password and 401 with a wrong one.
func EnsureUser(config []byte, user, bcryptHash string) ([]byte, bool, error) {
	if strings.TrimSpace(user) == "" {
		return nil, false, errors.New("an AdGuard admin account needs a username")
	}
	if !strings.HasPrefix(bcryptHash, "$2") {
		return nil, false, fmt.Errorf("the AdGuard password must be a bcrypt hash, got %q", bcryptHash)
	}
	switch InspectUsers(config) {
	case UsersPresent:
		return config, false, nil
	case UsersUnknown:
		return nil, false, fmt.Errorf(
			"this AdGuard config has no top-level 'users:' key, so curfew will not edit it. "+
				"Set a password in the AdGuard UI at port %d instead, then re-run with the same "+
				"-adguard-password", DefaultPort)
	}
	block := fmt.Sprintf("users:\n- name: %s\n  password: %s", user, bcryptHash)
	out := bytes.Replace(config, []byte("users: []"), []byte(block), 1)
	if !bytes.Equal(out, config) {
		return out, true, nil
	}
	// A bare "users:" with nothing after it.
	lines := strings.Split(string(config), "\n")
	for i, line := range lines {
		if strings.TrimRight(line, " \t\r") == "users:" {
			lines[i] = block
			return []byte(strings.Join(lines, "\n")), true, nil
		}
	}
	return nil, false, errors.New("could not find the empty users list to replace, " +
		"so nothing was changed")
}

// Client talks to AdGuard's REST API.
//
// Every call carries credentials. With no admin account AdGuard accepts them
// happily and ignores them, which is precisely the state curfew exists to
// remove, so the absence of a challenge is treated as a finding rather than as
// convenience (see Secured).
type Client struct {
	BaseURL  string
	User     string
	Password string
	HTTP     *http.Client
	// FilterHTTP is used for the calls that make AdGuard DOWNLOAD a list and
	// rebuild its filtering engine, which are the slow ones. Measured on the
	// live router: a filter refresh had not answered after 10 seconds, so the
	// ordinary client timed out and curfew logged a failure for an operation
	// that was still running and went on to succeed. A misreported success is
	// worse than a slow call, so these get their own, far longer, budget.
	FilterHTTP *http.Client
}

// NewClient builds a client for a router address such as "192.168.1.1:3000".
func NewClient(addr, user, password string) *Client {
	base := addr
	if !strings.HasPrefix(base, "http://") && !strings.HasPrefix(base, "https://") {
		base = "http://" + base
	}
	return &Client{
		BaseURL:    strings.TrimRight(base, "/"),
		User:       user,
		Password:   password,
		HTTP:       &http.Client{Timeout: 10 * time.Second},
		FilterHTTP: &http.Client{Timeout: 3 * time.Minute},
	}
}

// doFilter issues a filter-list call, which AdGuard answers only after the
// download and the engine rebuild are done. See Client.FilterHTTP.
func (c *Client) doFilter(method, path string, body any) (int, []byte, error) {
	hc := c.FilterHTTP
	if hc == nil {
		hc = c.HTTP
	}
	return c.doWith(hc, method, path, body, true)
}

func (c *Client) do(method, path string, body any, authed bool) (int, []byte, error) {
	return c.doWith(c.HTTP, method, path, body, authed)
}

func (c *Client) doWith(hc *http.Client, method, path string, body any, authed bool) (int, []byte, error) {
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, r)
	if err != nil {
		return 0, nil, err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if authed && c.User != "" {
		req.SetBasicAuth(c.User, c.Password)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, data, nil
}

// Status is the subset of AdGuard's status this tool cares about.
type Status struct {
	Version           string `json:"version"`
	Running           bool   `json:"running"`
	ProtectionEnabled bool   `json:"protection_enabled"`
	DNSPort           int    `json:"dns_port"`
}

// Status reads AdGuard's status, authenticating.
func (c *Client) Status() (Status, error) {
	code, body, err := c.do(http.MethodGet, "/control/status", nil, true)
	if err != nil {
		return Status{}, fmt.Errorf("reaching AdGuard at %s: %w", c.BaseURL, err)
	}
	if code == http.StatusUnauthorized || code == http.StatusForbidden {
		return Status{}, fmt.Errorf("AdGuard at %s rejected the credentials for user %q (HTTP %d). "+
			"Pass the existing password with -adguard-password", c.BaseURL, c.User, code)
	}
	if code != http.StatusOK {
		return Status{}, fmt.Errorf("AdGuard at %s returned HTTP %d: %s",
			c.BaseURL, code, strings.TrimSpace(string(body)))
	}
	var s Status
	if err := json.Unmarshal(body, &s); err != nil {
		return Status{}, fmt.Errorf("parsing AdGuard's status: %w", err)
	}
	return s, nil
}

// Reachable reports whether anything is answering at all, without judging
// authentication. Used to tell "AdGuard is not running" apart from "AdGuard
// refused us", which are different problems with different fixes.
func (c *Client) Reachable() bool {
	code, _, err := c.do(http.MethodGet, "/control/status", nil, false)
	return err == nil && code != 0
}

// Secured reports whether AdGuard actually CHALLENGES an unauthenticated
// caller.
//
// This is the check that matters, and it is deliberately made against the
// running server rather than against the config file. A config with a user in
// it that AdGuard has not reloaded is still an open API, and the thing a child
// on the LAN meets is the server, not the file.
func (c *Client) Secured() (bool, error) {
	code, _, err := c.do(http.MethodGet, "/control/status", nil, false)
	if err != nil {
		return false, fmt.Errorf("reaching AdGuard at %s: %w", c.BaseURL, err)
	}
	return code == http.StatusUnauthorized || code == http.StatusForbidden, nil
}
