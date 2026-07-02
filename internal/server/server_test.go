package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"ipsets/internal/config"
	"ipsets/internal/store"
)

func TestCurrentIPUsesRemoteAddrByDefault(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	hash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	app := New(AppConfig{
		Config: config.Config{
			AdminUsername:           "admin",
			AdminPasswordHash:       hash.PasswordHash,
			AdminPasswordSalt:       hash.PasswordSalt,
			AdminPasswordIterations: hash.PasswordIterations,
		},
		Store: s,
	})

	login := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, login)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "ipsets_session" || !cookies[0].HttpOnly {
		t.Fatalf("login cookies = %#v, want HttpOnly ipsets_session", cookies)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.RemoteAddr = "203.0.113.42:4567"
	req.Header.Set("X-Forwarded-For", "198.51.100.99")
	req.AddCookie(cookies[0])
	rec = httptest.NewRecorder()

	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var body struct {
		CurrentIP string `json:"currentIP"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body.CurrentIP != "203.0.113.42" {
		t.Fatalf("CurrentIP = %q, want 203.0.113.42", body.CurrentIP)
	}
}

func TestCurrentIPUsesForwardedHeaderFromLoopbackProxy(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.RemoteAddr = "127.0.0.1:4567"
	req.Header.Set("X-Forwarded-For", "198.51.100.23, 127.0.0.1")

	if got := currentIP(req, false); got != "198.51.100.23" {
		t.Fatalf("currentIP() = %q, want forwarded client IP", got)
	}
}

func TestCurrentIPIgnoresSpoofedForwardedHeaderFromDirectClient(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.RemoteAddr = "203.0.113.10:4567"
	req.Header.Set("X-Forwarded-For", "198.51.100.23")

	if got := currentIP(req, false); got != "203.0.113.10" {
		t.Fatalf("currentIP() = %q, want direct remote IP", got)
	}
}

func TestCurrentIPSupportsStandardForwardedHeaderWhenProxyTrusted(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.RemoteAddr = "10.0.0.2:4567"
	req.Header.Set("Forwarded", `for="198.51.100.23";proto=https`)

	if got := currentIP(req, true); got != "198.51.100.23" {
		t.Fatalf("currentIP() = %q, want Forwarded header client IP", got)
	}
}

func TestAddCurrentIPRequiresAuthAndStoresNote(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	hash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	app := New(AppConfig{
		Config: config.Config{
			AdminUsername:           "admin",
			AdminPasswordHash:       hash.PasswordHash,
			AdminPasswordSalt:       hash.PasswordSalt,
			AdminPasswordIterations: hash.PasswordIterations,
		},
		Store: s,
	})

	unauth := httptest.NewRequest(http.MethodPost, "/api/whitelist/current", strings.NewReader(`{"note":"home"}`))
	unauth.RemoteAddr = "203.0.113.42:4567"
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, unauth)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unauth status = %d, want 401", rec.Code)
	}

	login := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, login)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest(http.MethodPost, "/api/whitelist/current", strings.NewReader(`{"note":"home"}`))
	req.RemoteAddr = "203.0.113.42:4567"
	req.AddCookie(rec.Result().Cookies()[0])
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if entries := s.List(); len(entries) != 1 || entries[0].IP != "203.0.113.42" || entries[0].Note != "home" {
		t.Fatalf("entries = %#v, want stored current IP with note", entries)
	}
}

func TestLoginRejectsWrongPasswordAndLogoutClearsSession(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	hash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	app := New(AppConfig{
		Config: config.Config{
			AdminUsername:           "admin",
			AdminPasswordHash:       hash.PasswordHash,
			AdminPasswordSalt:       hash.PasswordSalt,
			AdminPasswordIterations: hash.PasswordIterations,
		},
		Store: s,
	})

	bad := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"bad"}`))
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, bad)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("bad login status = %d, want 401", rec.Code)
	}

	good := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"admin","password":"secret"}`))
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, good)
	if rec.Code != http.StatusOK {
		t.Fatalf("good login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	session := rec.Result().Cookies()[0]

	logout := httptest.NewRequest(http.MethodPost, "/api/logout", nil)
	logout.AddCookie(session)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, logout)
	if rec.Code != http.StatusOK {
		t.Fatalf("logout status = %d, body = %s", rec.Code, rec.Body.String())
	}

	state := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	state.AddCookie(session)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, state)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("state after logout status = %d, want 401", rec.Code)
	}
}

func TestAuthenticatedUserCanUpdateNoteAndProtectedPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	entry, err := s.AddOrUpdate(netipMustParse("203.0.113.42"), "old")
	if err != nil {
		t.Fatalf("AddOrUpdate() error = %v", err)
	}
	hash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	app := New(AppConfig{
		Config: config.Config{
			ConfigPath:              path,
			ProtectedPorts:          []int{22},
			ProtectedPortsRaw:       "22",
			AdminUsername:           "admin",
			AdminPasswordHash:       hash.PasswordHash,
			AdminPasswordSalt:       hash.PasswordSalt,
			AdminPasswordIterations: hash.PasswordIterations,
		},
		Store: s,
	})
	session := loginCookie(t, app, "admin", "secret")

	noteReq := httptest.NewRequest(http.MethodPatch, "/api/whitelist/"+entry.ID, strings.NewReader(`{"note":"updated"}`))
	noteReq.AddCookie(session)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, noteReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("note status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := s.List()[0].Note; got != "updated" {
		t.Fatalf("Note = %q, want updated", got)
	}

	portsReq := httptest.NewRequest(http.MethodPut, "/api/config/ports", strings.NewReader(`{"protectedPorts":"8008,8080-8082"}`))
	portsReq.AddCookie(session)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, portsReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("ports status = %d, body = %s", rec.Code, rec.Body.String())
	}
	var body struct {
		ProtectedPorts []int  `json:"protectedPorts"`
		Raw            string `json:"protectedPortsRaw"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body.Raw != "8008,8080-8082" || len(body.ProtectedPorts) != 4 || body.ProtectedPorts[3] != 8082 {
		t.Fatalf("ports response = %#v", body)
	}
}

func TestApplyAndRestorePersistFirewallState(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	hash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	wall := &fakeFirewall{}
	app := New(AppConfig{
		Config: config.Config{
			ProtectedPorts:          []int{22},
			ProtectedPortsRaw:       "22",
			AdminUsername:           "admin",
			AdminPasswordHash:       hash.PasswordHash,
			AdminPasswordSalt:       hash.PasswordSalt,
			AdminPasswordIterations: hash.PasswordIterations,
		},
		Store: s,
		Wall:  wall,
	})
	session := loginCookie(t, app, "admin", "secret")

	applyReq := httptest.NewRequest(http.MethodPost, "/api/apply", strings.NewReader(`{}`))
	applyReq.AddCookie(session)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, applyReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := s.FirewallState(); got.Status != "applied" || got.Message != "规则已应用" || got.UpdatedAt.IsZero() {
		t.Fatalf("FirewallState after apply = %#v", got)
	}

	restoreReq := httptest.NewRequest(http.MethodPost, "/api/restore", strings.NewReader(`{}`))
	restoreReq.AddCookie(session)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, restoreReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("restore status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if got := s.FirewallState(); got.Status != "restored" || got.Message != "已恢复原始状态" || got.UpdatedAt.IsZero() {
		t.Fatalf("FirewallState after restore = %#v", got)
	}
}

func TestApplyUsesUpdatedProtectedPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	hash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	wall := &fakeFirewall{}
	app := New(AppConfig{
		Config: config.Config{
			ConfigPath:              path,
			ProtectedPorts:          []int{22},
			ProtectedPortsRaw:       "22",
			AdminUsername:           "admin",
			AdminPasswordHash:       hash.PasswordHash,
			AdminPasswordSalt:       hash.PasswordSalt,
			AdminPasswordIterations: hash.PasswordIterations,
		},
		Store: s,
		Wall:  wall,
	})
	session := loginCookie(t, app, "admin", "secret")

	portsReq := httptest.NewRequest(http.MethodPut, "/api/config/ports", strings.NewReader(`{"protectedPorts":"8008,8080-8082"}`))
	portsReq.AddCookie(session)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, portsReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("ports status = %d, body = %s", rec.Code, rec.Body.String())
	}

	applyReq := httptest.NewRequest(http.MethodPost, "/api/apply", strings.NewReader(`{}`))
	applyReq.AddCookie(session)
	rec = httptest.NewRecorder()
	app.ServeHTTP(rec, applyReq)
	if rec.Code != http.StatusOK {
		t.Fatalf("apply status = %d, body = %s", rec.Code, rec.Body.String())
	}

	want := []int{8008, 8080, 8081, 8082}
	if !reflect.DeepEqual(wall.appliedPorts, want) {
		t.Fatalf("applied ports = %v, want %v", wall.appliedPorts, want)
	}
}

func TestStateDetectsMissingRulesWhenStoredApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := s.UpdateFirewallState(store.FirewallState{Status: "applied", Message: "规则已应用"}); err != nil {
		t.Fatalf("UpdateFirewallState() error = %v", err)
	}
	hash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	app := New(AppConfig{
		Config: config.Config{
			AdminUsername:           "admin",
			AdminPasswordHash:       hash.PasswordHash,
			AdminPasswordSalt:       hash.PasswordSalt,
			AdminPasswordIterations: hash.PasswordIterations,
		},
		Store: s,
		Wall:  &fakeFirewall{status: "not_applied"},
	})
	session := loginCookie(t, app, "admin", "secret")

	req := httptest.NewRequest(http.MethodGet, "/api/state", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("state status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var body struct {
		FirewallStatus string              `json:"firewallStatus"`
		FirewallState  store.FirewallState `json:"firewallState"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body.FirewallStatus != "not_applied" {
		t.Fatalf("FirewallStatus = %q, want not_applied", body.FirewallStatus)
	}
	if body.FirewallState.Status != "error" || !strings.Contains(body.FirewallState.Message, "当前未检测到防火墙规则") {
		t.Fatalf("FirewallState = %#v, want persisted drift error", body.FirewallState)
	}
	if got := s.FirewallState(); got.Status != "error" || !strings.Contains(got.Message, "当前未检测到防火墙规则") {
		t.Fatalf("persisted FirewallState = %#v, want drift error", got)
	}
}

func TestApplyFailurePersistsFirewallError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	hash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	app := New(AppConfig{
		Config: config.Config{
			AdminUsername:           "admin",
			AdminPasswordHash:       hash.PasswordHash,
			AdminPasswordSalt:       hash.PasswordSalt,
			AdminPasswordIterations: hash.PasswordIterations,
		},
		Store: s,
		Wall:  &fakeFirewall{applyErr: errors.New("boom")},
	})
	session := loginCookie(t, app, "admin", "secret")

	req := httptest.NewRequest(http.MethodPost, "/api/apply", strings.NewReader(`{}`))
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("apply status = %d, want 500", rec.Code)
	}
	if got := s.FirewallState(); got.Status != "error" || !strings.Contains(got.Message, "boom") || got.UpdatedAt.IsZero() {
		t.Fatalf("FirewallState after apply error = %#v", got)
	}
}

type fakeFirewall struct {
	applyErr     error
	restoreErr   error
	status       string
	appliedPorts []int
}

func (f *fakeFirewall) Apply(_ context.Context, ports []int, _ []store.Entry) error {
	f.appliedPorts = append([]int(nil), ports...)
	return f.applyErr
}

func (f *fakeFirewall) Restore(context.Context) error {
	return f.restoreErr
}

func (f *fakeFirewall) Status(context.Context) string {
	if f.status == "" {
		return "not_applied"
	}
	return f.status
}

func loginCookie(t *testing.T, app *App, username, password string) *http.Cookie {
	t.Helper()
	login := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"`+username+`","password":"`+password+`"}`))
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, login)
	if rec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", rec.Code, rec.Body.String())
	}
	return rec.Result().Cookies()[0]
}

func netipMustParse(raw string) netip.Addr {
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		panic(err)
	}
	return ip
}
