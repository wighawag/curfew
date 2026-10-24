package main

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wighawag/curfew/internal/leases"
	"github.com/wighawag/curfew/internal/registry"
)

// `curfew set-ip` edits ONLY the local device file. These tests point it at a
// temp file via -registry, so the real config/local/devices.json is never
// read or written.

func tempRegistry(t *testing.T, devices ...registry.Device) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "devices.json")
	if err := registry.Save(path, &registry.Registry{Devices: devices}); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadIP(t *testing.T, path, mac string) string {
	t.Helper()
	r, err := registry.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range r.Devices {
		if d.MAC == mac {
			return d.IP
		}
	}
	t.Fatalf("%s vanished from the registry", mac)
	return ""
}

func TestSetIPByNameEditsTheLocalFileAndPointsAtPush(t *testing.T) {
	path := tempRegistry(t, registry.Device{MAC: "84:47:09:84:8e:b2", Name: "shyrka"})
	msg, err := setIP(path, "shyrka", "192.168.1.150", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := loadIP(t, path, "84:47:09:84:8e:b2"); got != "192.168.1.150" {
		t.Errorf("not saved, got %q", got)
	}
	if !strings.Contains(msg, "curfew push") {
		t.Errorf("the message should say how to apply it: %q", msg)
	}
}

func TestSetIPClearByMAC(t *testing.T) {
	path := tempRegistry(t, registry.Device{MAC: "84:47:09:84:8e:b2", Name: "shyrka", IP: "192.168.1.150"})
	if _, err := setIP(path, "84-47-09-84-8E-B2", "", true); err != nil {
		t.Fatal(err)
	}
	if got := loadIP(t, path, "84:47:09:84:8e:b2"); got != "" {
		t.Errorf("not cleared, got %q", got)
	}
}

func TestSetIPRefusesBadInputAndWritesNothing(t *testing.T) {
	path := tempRegistry(t,
		registry.Device{MAC: "84:47:09:84:8e:b2", Name: "shyrka"},
		registry.Device{MAC: "f8:25:51:09:38:38", Name: "printer", IP: "192.168.1.10"})
	for _, c := range []struct{ ref, ip string }{
		{"nobody", "192.168.1.150"},
		{"shyrka", "not-an-ip"},
		{"shyrka", "192.168.1.10"}, // the printer's
	} {
		if _, err := setIP(path, c.ref, c.ip, false); err == nil {
			t.Errorf("set-ip %s %s was accepted", c.ref, c.ip)
		}
	}
	if got := loadIP(t, path, "84:47:09:84:8e:b2"); got != "" {
		t.Errorf("a refused address was written: %q", got)
	}
}

func TestParseSetIPArgsAcceptsFlagsEitherSide(t *testing.T) {
	for _, args := range [][]string{
		{"shyrka", "--clear"},
		{"--clear", "shyrka"},
		{"-registry", "x.json", "shyrka", "--clear"},
	} {
		a, err := parseSetIPArgs(args)
		if err != nil || a.ref != "shyrka" || !a.clear || a.ip != "" {
			t.Errorf("%v: got %+v, %v", args, a, err)
		}
	}
	a, err := parseSetIPArgs([]string{"shyrka", "192.168.1.150"})
	if err != nil || a.ref != "shyrka" || a.ip != "192.168.1.150" || a.clear {
		t.Errorf("got %+v, %v", a, err)
	}
	for _, bad := range [][]string{{}, {"shyrka"}, {"shyrka", "1.2.3.4", "--clear"}, {"a", "b", "c"}} {
		if _, err := parseSetIPArgs(bad); err == nil {
			t.Errorf("%v was accepted", bad)
		}
	}
}

// ---- what push checks against the router before writing anything ----

func pushSurvey(t *testing.T) leases.Survey {
	t.Helper()
	lan, err := leases.ParseLAN("network.lan.ipaddr='192.168.1.1/24'\n", "")
	if err != nil {
		t.Fatal(err)
	}
	return leases.Survey{
		LAN: lan,
		Hosts: []leases.Host{
			{Section: "@host[0]", MAC: "aa:aa:aa:aa:aa:aa", IP: "192.168.1.11"},
			{Section: leases.SectionFor("84:47:09:84:8e:b2"), MAC: "84:47:09:84:8e:b2", IP: "192.168.1.226"},
		},
		Leases: []leases.Lease{{MAC: "84:47:09:84:8e:b2", IP: "192.168.1.226", Expires: time.Now().Add(time.Hour)}},
		Now:    time.Now(),
	}
}

func TestPushChecksRefuseAnInvalidFixedAddress(t *testing.T) {
	local := &registry.Registry{Devices: []registry.Device{
		{MAC: "84:47:09:84:8e:b2", Name: "shyrka", IP: "192.168.1.11"},
	}}
	errs, _ := checkPushAddresses(pushSurvey(t), local, &registry.Registry{})
	if len(errs) != 1 || !strings.Contains(errs[0], "shyrka") || !strings.Contains(errs[0], "@host[0]") {
		t.Errorf("want one refusal naming the device and the holder, got %v", errs)
	}
}

func TestPushChecksExplainAChangedFixedAddress(t *testing.T) {
	local := &registry.Registry{Devices: []registry.Device{
		{MAC: "84:47:09:84:8e:b2", Name: "shyrka", IP: "192.168.1.150"},
	}}
	errs, notes := checkPushAddresses(pushSurvey(t), local, &registry.Registry{Devices: []registry.Device{
		{MAC: "84:47:09:84:8e:b2", Name: "shyrka"},
	}})
	if len(errs) != 0 {
		t.Fatalf("unexpected refusal: %v", errs)
	}
	all := strings.Join(notes, "\n")
	for _, want := range []string{"shyrka", "192.168.1.150", "next DHCP renewal", "inside the DHCP pool"} {
		if !strings.Contains(all, want) {
			t.Errorf("the push output should say %q:\n%s", want, all)
		}
	}
}

// An address the router already has is not news, so push stays quiet about it.
func TestPushChecksSayNothingAboutAnUnchangedAddress(t *testing.T) {
	same := &registry.Registry{Devices: []registry.Device{
		{MAC: "84:47:09:84:8e:b2", Name: "shyrka", IP: "192.168.1.150"},
	}}
	_, notes := checkPushAddresses(pushSurvey(t), same, same)
	if len(notes) != 0 {
		t.Errorf("an unchanged address produced output: %v", notes)
	}
}

func TestPushRefusesAnOldDaemonWhenAnyFixedAddressIsSet(t *testing.T) {
	with := &registry.Registry{Devices: []registry.Device{{MAC: "84:47:09:84:8e:b2", IP: "192.168.1.150"}}}
	without := &registry.Registry{Devices: []registry.Device{{MAC: "84:47:09:84:8e:b2"}}}
	if err := requireFixedAddressSupport(false, with, "root@r"); err == nil ||
		!strings.Contains(err.Error(), "curfew update root@r") {
		t.Errorf("an old daemon must be refused with the fix named, got %v", err)
	}
	if err := requireFixedAddressSupport(false, without, "root@r"); err != nil {
		t.Errorf("no fixed address, nothing for an old daemon to drop: %v", err)
	}
	if err := requireFixedAddressSupport(true, with, "root@r"); err != nil {
		t.Errorf("a current daemon was refused: %v", err)
	}
}
