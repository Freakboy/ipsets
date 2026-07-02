package store

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
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
