package store

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAddOrUpdatePersistsEntryByIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	ip := netip.MustParseAddr("203.0.113.42")
	first, err := s.AddOrUpdate(ip, "office")
	if err != nil {
		t.Fatalf("AddOrUpdate() first error = %v", err)
	}
	second, err := s.AddOrUpdate(ip, "home")
	if err != nil {
		t.Fatalf("AddOrUpdate() second error = %v", err)
	}

	if first.ID != second.ID {
		t.Fatalf("IDs differ: %q vs %q", first.ID, second.ID)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open() reopened error = %v", err)
	}
	entries := reopened.List()
	if len(entries) != 1 {
		t.Fatalf("entry count = %d, want 1", len(entries))
	}
	if entries[0].Note != "home" {
		t.Fatalf("Note = %q, want home", entries[0].Note)
	}

	var file struct {
		Whitelist []Entry `json:"whitelist"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(file.Whitelist) != 1 || file.Whitelist[0].Note != "home" {
		t.Fatalf("config whitelist = %#v, want persisted entry", file.Whitelist)
	}
}

func TestDeleteRemovesEntry(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	entry, err := s.AddOrUpdate(netip.MustParseAddr("198.51.100.10"), "temporary")
	if err != nil {
		t.Fatalf("AddOrUpdate() error = %v", err)
	}

	if err := s.Delete(entry.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if got := s.List(); len(got) != 0 {
		t.Fatalf("List() length = %d, want 0", len(got))
	}
}

func TestListSortsByNumericIP(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"whitelist":[{"id":"10.0.0.2","ip":"10.0.0.2"},{"id":"2.0.0.10","ip":"2.0.0.10"},{"id":"10.0.0.0/8","ip":"10.0.0.0/8"},{"id":"192.168.1.0/24","ip":"192.168.1.0/24"}]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	entries := s.List()
	want := []string{"2.0.0.10", "10.0.0.0/8", "10.0.0.2", "192.168.1.0/24"}
	for i, entry := range entries {
		if entry.IP != want[i] {
			t.Fatalf("List()[%d].IP = %q, want %q; entries = %#v", i, entry.IP, want[i], entries)
		}
	}
}

func TestReorderPersistsWhitelistOrder(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2", "192.0.2.3"} {
		if _, err := s.AddOrUpdateAddress(ip, ""); err != nil {
			t.Fatalf("AddOrUpdateAddress(%q) error = %v", ip, err)
		}
	}
	if err := s.UpdateFirewallState(FirewallState{Status: "applied", Message: "ok"}); err != nil {
		t.Fatalf("UpdateFirewallState() error = %v", err)
	}

	if err := s.Reorder([]string{"192.0.2.3", "192.0.2.1", "192.0.2.2"}); err != nil {
		t.Fatalf("Reorder() error = %v", err)
	}
	entries := s.List()
	want := []string{"192.0.2.3", "192.0.2.1", "192.0.2.2"}
	for i, entry := range entries {
		if entry.IP != want[i] || entry.Order != i {
			t.Fatalf("List()[%d] = %#v, want IP %q and order %d", i, entry, want[i], i)
		}
	}
	if got := s.FirewallState(); got.Status != "applied" {
		t.Fatalf("FirewallState() = %#v, display reorder must not mark rules pending", got)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open() reopened error = %v", err)
	}
	entries = reopened.List()
	for i, entry := range entries {
		if entry.IP != want[i] || entry.Order != i {
			t.Fatalf("reopened List()[%d] = %#v, want IP %q and order %d", i, entry, want[i], i)
		}
	}
}

func TestReorderRejectsIncompleteOrder(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := s.AddOrUpdateAddress("192.0.2.1", ""); err != nil {
		t.Fatalf("AddOrUpdateAddress() error = %v", err)
	}
	if err := s.Reorder(nil); err == nil {
		t.Fatal("Reorder() error = nil, want incomplete order rejection")
	}
}

func TestReorderValidatesBeforeChangingEntries(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if _, err := s.AddOrUpdateAddress(ip, ""); err != nil {
			t.Fatalf("AddOrUpdateAddress(%q) error = %v", ip, err)
		}
	}
	if err := s.Reorder([]string{"192.0.2.2", "unknown"}); err == nil {
		t.Fatal("Reorder() error = nil, want unknown entry rejection")
	}
	entries := s.List()
	if entries[0].IP != "192.0.2.1" || entries[0].Order != 0 || entries[1].IP != "192.0.2.2" || entries[1].Order != 1 {
		t.Fatalf("entries changed after rejected reorder: %#v", entries)
	}
}

func TestImportConfigReplacesEntriesAndMarksRulesPending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"custom":"kept","protectedPorts":"22","whitelist":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	entries := []Entry{{ID: "192.0.2.10", IP: "192.0.2.10", Order: 0, Note: "imported"}}
	data := []byte(`{"custom":"kept","protectedPorts":"443","whitelist":[],"firewallState":{"status":"applied","message":"old"}}`)
	if err := s.ImportConfig(data, entries); err != nil {
		t.Fatalf("ImportConfig() error = %v", err)
	}
	if got := s.List(); len(got) != 1 || got[0].IP != "192.0.2.10" || got[0].Note != "imported" {
		t.Fatalf("List() = %#v, want imported entry", got)
	}
	if got := s.FirewallState(); got.Status != "pending" || got.Message != "配置已导入，需要重新应用规则" {
		t.Fatalf("FirewallState() = %#v, want pending import state", got)
	}
	var raw map[string]json.RawMessage
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := json.Unmarshal(persisted, &raw); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if string(raw["custom"]) != `"kept"` || !strings.Contains(string(raw["whitelist"]), "192.0.2.10") {
		t.Fatalf("persisted config = %s, want custom field and imported whitelist", persisted)
	}
}

func TestSyncSourceReplacesManagedEntriesOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := s.AddOrUpdateAddress("203.0.113.42", "manual"); err != nil {
		t.Fatalf("AddOrUpdateAddress() manual error = %v", err)
	}
	result, err := s.SyncSource("cloudflare", []string{"198.51.100.0/24"}, "Cloudflare proxy IP range")
	if err != nil {
		t.Fatalf("SyncSource() first error = %v", err)
	}
	if result.Added != 1 || result.Updated != 0 || result.Removed != 0 {
		t.Fatalf("SyncSource() first result = %#v, want 1 added", result)
	}

	result, err = s.SyncSource("cloudflare", []string{"198.51.100.0/24", "198.51.101.0/24"}, "Cloudflare proxy IP range")
	if err != nil {
		t.Fatalf("SyncSource() second error = %v", err)
	}
	if result.Added != 1 || result.Updated != 1 || result.Removed != 0 {
		t.Fatalf("SyncSource() second result = %#v, want 1 added, 1 updated, 0 removed", result)
	}

	entries := s.List()
	if len(entries) != 3 {
		t.Fatalf("List() length = %d, want manual plus 2 Cloudflare entries: %#v", len(entries), entries)
	}
	seen := map[string]Entry{}
	for _, entry := range entries {
		seen[entry.IP] = entry
	}
	if seen["203.0.113.42"].Source != "" || seen["203.0.113.42"].Note != "manual" {
		t.Fatalf("manual entry changed: %#v", seen["203.0.113.42"])
	}
	for _, ip := range []string{"198.51.100.0/24", "198.51.101.0/24"} {
		if seen[ip].Source != "cloudflare" || seen[ip].Note != "Cloudflare proxy IP range" {
			t.Fatalf("managed entry %s = %#v, want Cloudflare source and note", ip, seen[ip])
		}
	}
}

func TestUpdateNotePersistsEntryNote(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	entry, err := s.AddOrUpdate(netip.MustParseAddr("203.0.113.42"), "old")
	if err != nil {
		t.Fatalf("AddOrUpdate() error = %v", err)
	}

	updated, err := s.UpdateNote(entry.ID, "new note")
	if err != nil {
		t.Fatalf("UpdateNote() error = %v", err)
	}
	if updated.Note != "new note" {
		t.Fatalf("updated Note = %q, want new note", updated.Note)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open() reopened error = %v", err)
	}
	if got := reopened.List()[0].Note; got != "new note" {
		t.Fatalf("persisted Note = %q, want new note", got)
	}
}

func TestUpdateProtectedPortsPersistsConfigField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"protectedPorts":"22","whitelist":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if err := s.UpdateProtectedPorts("8008,8080-8090"); err != nil {
		t.Fatalf("UpdateProtectedPorts() error = %v", err)
	}

	var file struct {
		ProtectedPorts string `json:"protectedPorts"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if file.ProtectedPorts != "8008,8080-8090" {
		t.Fatalf("ProtectedPorts = %q, want 8008,8080-8090", file.ProtectedPorts)
	}
}

func TestUpdateFirewallStatePersistsStatus(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"protectedPorts":"22","whitelist":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	if err := s.UpdateFirewallState(FirewallState{Status: "applied", Message: "ok"}); err != nil {
		t.Fatalf("UpdateFirewallState() error = %v", err)
	}

	var file struct {
		FirewallState FirewallState `json:"firewallState"`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if err := json.Unmarshal(data, &file); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if file.FirewallState.Status != "applied" || file.FirewallState.Message != "ok" || file.FirewallState.UpdatedAt.IsZero() {
		t.Fatalf("FirewallState = %#v, want applied status with timestamp", file.FirewallState)
	}

	reopened, err := Open(path)
	if err != nil {
		t.Fatalf("Open() reopened error = %v", err)
	}
	if got := reopened.FirewallState(); got.Status != "applied" || got.Message != "ok" {
		t.Fatalf("FirewallState() = %#v, want persisted applied state", got)
	}
}

func TestMutationsMarkFirewallStatePending(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"protectedPorts":"22","firewallState":{"status":"applied","message":"ok","updatedAt":"2026-01-01T00:00:00Z"},"whitelist":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	s, err := Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	entry, err := s.AddOrUpdate(netip.MustParseAddr("203.0.113.42"), "office")
	if err != nil {
		t.Fatalf("AddOrUpdate() error = %v", err)
	}
	assertPending(t, s.FirewallState())

	if err := s.UpdateFirewallState(FirewallState{Status: "applied", Message: "ok"}); err != nil {
		t.Fatalf("UpdateFirewallState() reset error = %v", err)
	}
	if _, err := s.UpdateNote(entry.ID, "home"); err != nil {
		t.Fatalf("UpdateNote() error = %v", err)
	}
	assertPending(t, s.FirewallState())

	if err := s.UpdateFirewallState(FirewallState{Status: "applied", Message: "ok"}); err != nil {
		t.Fatalf("UpdateFirewallState() reset error = %v", err)
	}
	if err := s.UpdateProtectedPorts("22,443"); err != nil {
		t.Fatalf("UpdateProtectedPorts() error = %v", err)
	}
	assertPending(t, s.FirewallState())

	if err := s.UpdateFirewallState(FirewallState{Status: "applied", Message: "ok"}); err != nil {
		t.Fatalf("UpdateFirewallState() reset error = %v", err)
	}
	if err := s.Delete(entry.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	assertPending(t, s.FirewallState())
}

func assertPending(t *testing.T, state FirewallState) {
	t.Helper()
	if state.Status != "pending" || state.Message != "配置已修改，需要重新应用规则" || state.UpdatedAt.IsZero() {
		t.Fatalf("FirewallState = %#v, want pending reapply state", state)
	}
}
