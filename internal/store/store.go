package store

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

type Entry struct {
	ID        string    `json:"id"`
	IP        string    `json:"ip"`
	Order     int       `json:"order"`
	Note      string    `json:"note"`
	Source    string    `json:"source,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type SyncResult struct {
	Entries []Entry
	Added   int
	Updated int
	Removed int
}

type FirewallState struct {
	Status    string    `json:"status"`
	Message   string    `json:"message"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type Store struct {
	mu            sync.Mutex
	path          string
	entries       map[string]Entry
	firewallState FirewallState
}

func Open(path string) (*Store, error) {
	s := &Store{
		path:    path,
		entries: map[string]Entry{},
	}

	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return s, nil
	}

	entries, state, err := decodeConfig(data)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.ID == "" {
			entry.ID = entry.IP
		}
		s.entries[entry.ID] = entry
	}
	s.firewallState = state
	return s, nil
}

func decodeConfig(data []byte) ([]Entry, FirewallState, error) {
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "[") {
		var entries []Entry
		if err := json.Unmarshal(data, &entries); err != nil {
			return nil, FirewallState{}, err
		}
		return entries, FirewallState{}, nil
	}

	var file struct {
		Whitelist     []Entry       `json:"whitelist"`
		FirewallState FirewallState `json:"firewallState"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, FirewallState{}, err
	}
	return file.Whitelist, file.FirewallState, nil
}

func (s *Store) AddOrUpdate(ip netip.Addr, note string) (Entry, error) {
	return s.AddOrUpdateAddress(ip.String(), note)
}

func (s *Store) AddOrUpdateAddress(address string, note string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	id := strings.TrimSpace(address)
	entry, exists := s.entries[id]
	if !exists {
		entry = Entry{
			ID:        id,
			IP:        id,
			Order:     s.nextOrderLocked(),
			CreatedAt: now,
		}
	}
	entry.Note = strings.TrimSpace(note)
	entry.UpdatedAt = now
	s.entries[id] = entry
	s.markPendingLocked()

	if err := s.saveLocked(); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

func (s *Store) SyncSource(source string, addresses []string, note string) (SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	source = strings.TrimSpace(source)
	if source == "" {
		return SyncResult{}, errors.New("source is required")
	}

	now := time.Now().UTC()
	desired := map[string]bool{}
	for _, address := range addresses {
		address = strings.TrimSpace(address)
		if address != "" {
			desired[address] = true
		}
	}
	orderedDesired := make([]string, 0, len(desired))
	for address := range desired {
		orderedDesired = append(orderedDesired, address)
	}
	sort.Slice(orderedDesired, func(i, j int) bool { return compareIP(orderedDesired[i], orderedDesired[j]) < 0 })

	result := SyncResult{}
	for id, entry := range s.entries {
		if entry.Source == source && !desired[id] {
			delete(s.entries, id)
			result.Removed++
		}
	}

	for _, address := range orderedDesired {
		entry, exists := s.entries[address]
		if !exists {
			entry = Entry{
				ID:        address,
				IP:        address,
				Order:     s.nextOrderLocked(),
				CreatedAt: now,
			}
			result.Added++
		} else {
			result.Updated++
		}
		entry.Note = strings.TrimSpace(note)
		entry.Source = source
		entry.UpdatedAt = now
		s.entries[address] = entry
		result.Entries = append(result.Entries, entry)
	}
	sort.SliceStable(result.Entries, func(i, j int) bool {
		if result.Entries[i].Order != result.Entries[j].Order {
			return result.Entries[i].Order < result.Entries[j].Order
		}
		return compareIP(result.Entries[i].IP, result.Entries[j].IP) < 0
	})

	s.markPendingLocked()
	if err := s.saveLocked(); err != nil {
		return SyncResult{}, err
	}
	return result, nil
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.entries, id)
	s.markPendingLocked()
	return s.saveLocked()
}

func (s *Store) UpdateNote(id string, note string) (Entry, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entry, ok := s.entries[id]
	if !ok {
		return Entry{}, os.ErrNotExist
	}
	entry.Note = strings.TrimSpace(note)
	entry.UpdatedAt = time.Now().UTC()
	s.entries[id] = entry
	s.markPendingLocked()
	if err := s.saveLocked(); err != nil {
		return Entry{}, err
	}
	return entry, nil
}

func (s *Store) Reorder(ids []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(ids) != len(s.entries) {
		return errors.New("order must include every whitelist entry")
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if seen[id] {
			return errors.New("order contains duplicate whitelist entries")
		}
		if _, ok := s.entries[id]; !ok {
			return errors.New("order contains an unknown whitelist entry")
		}
		seen[id] = true
	}
	for order, id := range ids {
		entry := s.entries[id]
		entry.Order = order
		s.entries[id] = entry
	}
	return s.saveLocked()
}

func (s *Store) UpdateProtectedPorts(raw string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.markPendingLocked()
	return s.saveRawFieldLocked("protectedPorts", strings.TrimSpace(raw))
}

func (s *Store) UpdateFirewallState(state FirewallState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if state.UpdatedAt.IsZero() {
		state.UpdatedAt = time.Now().UTC()
	}
	s.firewallState = state
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	raw, err := s.readRawConfigLocked()
	if err != nil {
		return err
	}
	raw["firewallState"] = data
	return s.writeRawConfigLocked(raw)
}

func (s *Store) FirewallState() FirewallState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.firewallState
}

func (s *Store) List() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries := make([]Entry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Order != entries[j].Order {
			return entries[i].Order < entries[j].Order
		}
		return compareIP(entries[i].IP, entries[j].IP) < 0
	})
	return entries
}

func compareIP(left, right string) int {
	leftAddr, leftBits, leftOK := sortableIP(left)
	rightAddr, rightBits, rightOK := sortableIP(right)
	if leftOK && rightOK {
		if leftAddr.Is4() != rightAddr.Is4() {
			if leftAddr.Is4() {
				return -1
			}
			return 1
		}
		if compared := leftAddr.Compare(rightAddr); compared != 0 {
			return compared
		}
		if leftBits != rightBits {
			if leftBits < rightBits {
				return -1
			}
			return 1
		}
	}
	if left < right {
		return -1
	}
	if left > right {
		return 1
	}
	return 0
}

func sortableIP(value string) (netip.Addr, int, bool) {
	if prefix, err := netip.ParsePrefix(value); err == nil {
		return prefix.Addr(), prefix.Bits(), true
	}
	if address, err := netip.ParseAddr(value); err == nil {
		bits := 128
		if address.Is4() {
			bits = 32
		}
		return address, bits, true
	}
	return netip.Addr{}, 0, false
}

func (s *Store) saveLocked() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	entries := make([]Entry, 0, len(s.entries))
	for _, entry := range s.entries {
		entries = append(entries, entry)
	}
	sort.SliceStable(entries, func(i, j int) bool {
		if entries[i].Order != entries[j].Order {
			return entries[i].Order < entries[j].Order
		}
		return compareIP(entries[i].IP, entries[j].IP) < 0
	})

	raw, err := s.readRawConfigLocked()
	if err != nil {
		return err
	}

	whitelist, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	raw["whitelist"] = whitelist
	if err := s.writeFirewallStateRawLocked(raw); err != nil {
		return err
	}
	return s.writeRawConfigLocked(raw)
}

func (s *Store) nextOrderLocked() int {
	order := 0
	for _, entry := range s.entries {
		if entry.Order >= order {
			order = entry.Order + 1
		}
	}
	return order
}

func (s *Store) saveRawFieldLocked(field string, value string) error {
	raw, err := s.readRawConfigLocked()
	if err != nil {
		return err
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw[field] = data
	if err := s.writeFirewallStateRawLocked(raw); err != nil {
		return err
	}
	return s.writeRawConfigLocked(raw)
}

func (s *Store) markPendingLocked() {
	s.firewallState = FirewallState{
		Status:    "pending",
		Message:   "配置已修改，需要重新应用规则",
		UpdatedAt: time.Now().UTC(),
	}
}

func (s *Store) writeFirewallStateRawLocked(raw map[string]json.RawMessage) error {
	if s.firewallState.Status == "" {
		return nil
	}
	data, err := json.Marshal(s.firewallState)
	if err != nil {
		return err
	}
	raw["firewallState"] = data
	return nil
}

func (s *Store) readRawConfigLocked() (map[string]json.RawMessage, error) {
	raw := map[string]json.RawMessage{}
	if data, err := os.ReadFile(s.path); err == nil && len(strings.TrimSpace(string(data))) > 0 && !strings.HasPrefix(strings.TrimSpace(string(data)), "[") {
		if err := json.Unmarshal(data, &raw); err != nil {
			return nil, err
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return raw, nil
}

func (s *Store) writeRawConfigLocked(raw map[string]json.RawMessage) error {
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}
