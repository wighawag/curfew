package adguard

import (
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// The config AdGuard itself writes when the legacy setup script has run: an
// empty users list, which means the whole REST API is unauthenticated.
const openConfig = `http:
  address: 0.0.0.0:3000
  session_ttl: 1h
users: []
dns:
  bind_hosts:
  - 0.0.0.0
  port: 53
schema_version: 34
user_rules:
- '@@||eth.limo^'
`

const securedConfig = `http:
  address: 0.0.0.0:3000
users:
- name: someone
  password: $2a$10$abcdefghijklmnopqrstuv
dns:
  port: 53
`

func TestInspectUsersTellsTheThreeCasesApart(t *testing.T) {
	if got := InspectUsers([]byte(openConfig)); got != UsersEmpty {
		t.Errorf("an empty users list must read as UsersEmpty, got %v", got)
	}
	if got := InspectUsers([]byte(securedConfig)); got != UsersPresent {
		t.Errorf("an existing account must read as UsersPresent, got %v", got)
	}
	if got := InspectUsers([]byte("dns:\n  port: 53\n")); got != UsersUnknown {
		t.Errorf("a config with no users key must read as UsersUnknown, got %v", got)
	}
	// A bare "users:" followed by the next key is empty, not present.
	bare := "http:\n  address: x\nusers:\ndns:\n  port: 53\n"
	if got := InspectUsers([]byte(bare)); got != UsersEmpty {
		t.Errorf("a bare users key with no items must read as UsersEmpty, got %v", got)
	}
	// A bare "users:" followed by a list item IS present.
	withItem := "users:\n- name: a\n  password: b\ndns:\n  port: 53\n"
	if got := InspectUsers([]byte(withItem)); got != UsersPresent {
		t.Errorf("a list item after users: must read as UsersPresent, got %v", got)
	}
}

// An INDENTED users key belongs to some other section. Mistaking it for the
// top-level one would edit the wrong part of somebody's config.
func TestInspectUsersIgnoresANestedUsersKey(t *testing.T) {
	nested := "dns:\n  port: 53\nsomething:\n  users: []\n"
	if got := InspectUsers([]byte(nested)); got != UsersUnknown {
		t.Errorf("a nested users key must not be treated as the admin list, got %v", got)
	}
}

func TestEnsureUserClosesAnOpenConfig(t *testing.T) {
	hash, err := HashPassword("hunter2")
	if err != nil {
		t.Fatal(err)
	}
	out, changed, err := EnsureUser([]byte(openConfig), "parent", hash)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if !changed {
		t.Fatal("an unauthenticated config must be changed")
	}
	if InspectUsers(out) != UsersPresent {
		t.Errorf("the result still has no admin account:\n%s", out)
	}
	if !strings.Contains(string(out), "name: parent") {
		t.Errorf("the username is missing:\n%s", out)
	}
	// Everything else must survive. A hand-made exception being destroyed by a
	// reinstall is the defect ADR 0002 recorded, and this edit exists partly
	// to stop repeating it.
	if !strings.Contains(string(out), "@@||eth.limo^") {
		t.Errorf("a hand-made exception was destroyed:\n%s", out)
	}
	if !strings.Contains(string(out), "schema_version: 34") {
		t.Errorf("an unrelated setting was lost:\n%s", out)
	}
	// And the stored hash must actually verify, or the password would be one
	// nobody can use and the UI would be locked out.
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte("hunter2")); err != nil {
		t.Errorf("the stored hash does not match the password: %v", err)
	}
}

// Adopting somebody's existing AdGuard must never disturb their login.
func TestEnsureUserLeavesAnExistingAccountAlone(t *testing.T) {
	hash, _ := HashPassword("hunter2")
	out, changed, err := EnsureUser([]byte(securedConfig), "parent", hash)
	if err != nil {
		t.Fatalf("EnsureUser: %v", err)
	}
	if changed {
		t.Error("an existing admin account must not be replaced")
	}
	if string(out) != securedConfig {
		t.Errorf("the config was modified:\n%s", out)
	}
}

// A config we do not understand is a loud refusal, not a guess. Appending to
// somebody's working install because we could not find a key is how a
// diagnostic becomes an outage.
func TestEnsureUserRefusesAConfigItDoesNotUnderstand(t *testing.T) {
	_, _, err := EnsureUser([]byte("dns:\n  port: 53\n"), "parent", "$2a$10$x")
	if err == nil {
		t.Fatal("a config with no users key must be refused rather than edited")
	}
	if !strings.Contains(err.Error(), "AdGuard UI") {
		t.Errorf("the error must say what to do instead, got %v", err)
	}
}

func TestEnsureUserRejectsAPlaintextPassword(t *testing.T) {
	// Writing a plaintext password into the config would leave AdGuard unable
	// to authenticate anyone, which fails OPEN in appearance and closed in
	// practice, so it is refused at the door.
	if _, _, err := EnsureUser([]byte(openConfig), "parent", "hunter2"); err == nil {
		t.Error("a plaintext password must be refused: AdGuard stores bcrypt")
	}
	if _, _, err := EnsureUser([]byte(openConfig), "", "$2a$10$x"); err == nil {
		t.Error("an empty username must be refused")
	}
}

func TestHashPasswordRefusesAnEmptyPassword(t *testing.T) {
	if _, err := HashPassword("  "); err == nil {
		t.Error("an empty AdGuard password must be refused: it leaves the API open")
	}
}

func TestNewClientAcceptsAddressesWithAndWithoutAScheme(t *testing.T) {
	for _, in := range []string{"192.168.1.1:3000", "http://192.168.1.1:3000", "http://192.168.1.1:3000/"} {
		c := NewClient(in, "parent", "x")
		if c.BaseURL != "http://192.168.1.1:3000" {
			t.Errorf("NewClient(%q).BaseURL = %q", in, c.BaseURL)
		}
	}
}
