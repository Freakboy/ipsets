package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
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

func TestAddManualAcceptsCIDRWhitelistEntry(t *testing.T) {
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
	session := loginCookie(t, app, "admin", "secret")

	req := httptest.NewRequest(http.MethodPost, "/api/whitelist", strings.NewReader(`{"ip":"203.0.113.42/24","note":"office range"}`))
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if entries := s.List(); len(entries) != 1 || entries[0].IP != "203.0.113.0/24" || entries[0].ID != "203.0.113.0/24" {
		t.Fatalf("entries = %#v, want canonical CIDR entry", entries)
	}
}

func TestSyncCloudflareWhitelistEntries(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := s.AddOrUpdateAddress("203.0.113.42", "manual"); err != nil {
		t.Fatalf("AddOrUpdateAddress() error = %v", err)
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
		CloudflareRanges: func(context.Context) ([]string, error) {
			return []string{"198.51.100.42/24"}, nil
		},
	})
	session := loginCookie(t, app, "admin", "secret")

	req := httptest.NewRequest(http.MethodPost, "/api/whitelist/cloudflare", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Added   int           `json:"added"`
		Updated int           `json:"updated"`
		Removed int           `json:"removed"`
		Entries []store.Entry `json:"entries"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if body.Added != 1 || body.Updated != 0 || body.Removed != 0 || len(body.Entries) != 1 {
		t.Fatalf("sync response = %#v, want 1 Cloudflare entry added", body)
	}

	entries := s.List()
	seen := map[string]store.Entry{}
	for _, entry := range entries {
		seen[entry.IP] = entry
	}
	if seen["203.0.113.42"].Note != "manual" || seen["203.0.113.42"].Source != "" {
		t.Fatalf("manual entry changed: %#v", seen["203.0.113.42"])
	}
	if seen["198.51.100.0/24"].Source != "cloudflare" {
		t.Fatalf("Cloudflare entries missing source: %#v", entries)
	}
	if got := s.FirewallState(); got.Status != "pending" || got.UpdatedAt.IsZero() {
		t.Fatalf("FirewallState = %#v, want pending after Cloudflare sync", got)
	}
}

func TestReorderWhitelistEntries(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	for _, ip := range []string{"192.0.2.1", "192.0.2.2"} {
		if _, err := s.AddOrUpdateAddress(ip, ""); err != nil {
			t.Fatalf("AddOrUpdateAddress(%q) error = %v", ip, err)
		}
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
	session := loginCookie(t, app, "admin", "secret")
	req := httptest.NewRequest(http.MethodPut, "/api/whitelist/order", strings.NewReader(`{"ids":["192.0.2.2","192.0.2.1"]}`))
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	app.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", rec.Code, rec.Body.String())
	}
	entries := s.List()
	if entries[0].IP != "192.0.2.2" || entries[1].IP != "192.0.2.1" {
		t.Fatalf("entries = %#v, want reordered whitelist", entries)
	}
}

func TestExportAndImportConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	originalHash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() original error = %v", err)
	}
	original := fmt.Sprintf(`{"listenAddr":":8008","tableName":"ipsets","protectedPorts":"22","trustProxy":false,"admin":{"username":"admin","password":%q},"whitelist":[]}`,
		originalHash.PasswordHash)
	if err := os.WriteFile(path, []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	s, err := store.Open(path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	app := New(AppConfig{
		Config: config.Config{
			ListenAddr:              ":8008",
			TableName:               "ipsets",
			ConfigPath:              path,
			ProtectedPorts:          []int{22},
			ProtectedPortsRaw:       "22",
			AdminUsername:           "admin",
			AdminPasswordHash:       originalHash.PasswordHash,
			AdminPasswordSalt:       originalHash.PasswordSalt,
			AdminPasswordIterations: originalHash.PasswordIterations,
		},
		Store: s,
	})
	session := loginCookie(t, app, "admin", "secret")

	exportReq := httptest.NewRequest(http.MethodGet, "/api/config/export", nil)
	exportReq.AddCookie(session)
	exportRec := httptest.NewRecorder()
	app.ServeHTTP(exportRec, exportReq)
	if exportRec.Code != http.StatusOK || !strings.Contains(exportRec.Header().Get("Content-Disposition"), "ipsets-config.json") || !json.Valid(exportRec.Body.Bytes()) {
		t.Fatalf("export status = %d, headers = %#v, body = %s", exportRec.Code, exportRec.Header(), exportRec.Body.String())
	}

	imported := `{"listenAddr":":8008","tableName":"ipsets","protectedPorts":"443,80","trustProxy":true,"admin":{"username":"operator","password":"new-secret"},"whitelist":[{"ip":"192.0.2.42/24","note":"imported range"}]}`
	importReq := httptest.NewRequest(http.MethodPost, "/api/config/import", strings.NewReader(imported))
	importReq.AddCookie(session)
	importRec := httptest.NewRecorder()
	app.ServeHTTP(importRec, importReq)
	if importRec.Code != http.StatusOK {
		t.Fatalf("import status = %d, body = %s", importRec.Code, importRec.Body.String())
	}
	var importBody struct {
		RestartRequired bool `json:"restartRequired"`
	}
	if err := json.NewDecoder(importRec.Body).Decode(&importBody); err != nil {
		t.Fatalf("Decode(import) error = %v", err)
	}
	if importBody.RestartRequired {
		t.Fatal("RestartRequired = true, want hot-reloadable import")
	}
	if entries := s.List(); len(entries) != 1 || entries[0].IP != "192.0.2.0/24" || entries[0].Note != "imported range" {
		t.Fatalf("entries = %#v, want normalized imported whitelist", entries)
	}
	if state := s.FirewallState(); state.Status != "pending" {
		t.Fatalf("FirewallState() = %#v, want pending", state)
	}
	if cfg := app.configSnapshot(); cfg.ProtectedPortsRaw != "80,443" || !cfg.TrustProxy || !cfg.VerifyPassword("operator", "new-secret") {
		t.Fatalf("runtime config = %#v, want imported hot settings", cfg)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(imported config) error = %v", err)
	}
	if strings.Contains(string(persisted), "new-secret") || !strings.Contains(string(persisted), `"password": "$2`) {
		t.Fatalf("imported password was not persisted as bcrypt: %s", persisted)
	}
}

func TestApplyRejectsImportedTableNameUntilRestart(t *testing.T) {
	app := &App{tableRestartRequired: true}
	req := httptest.NewRequest(http.MethodPost, "/api/apply", strings.NewReader(`{}`))
	rec := httptest.NewRecorder()
	app.handleApply(rec, req)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "请重启 IPSets") {
		t.Fatalf("status = %d, body = %s, want restart conflict", rec.Code, rec.Body.String())
	}
}

func TestManagementAPIRequiresAuthentication(t *testing.T) {
	s, err := store.Open(filepath.Join(t.TempDir(), "config.json"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	hash, err := config.HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	cfCalled := false
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
		Wall:  &fakeFirewall{},
		CloudflareRanges: func(context.Context) ([]string, error) {
			cfCalled = true
			return []string{"198.51.100.0/24"}, nil
		},
	})

	for _, tc := range []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/logout", `{}`},
		{http.MethodGet, "/api/state", ``},
		{http.MethodPost, "/api/whitelist/current", `{"note":"home"}`},
		{http.MethodPost, "/api/whitelist/cloudflare", `{}`},
		{http.MethodPost, "/api/whitelist", `{"ip":"203.0.113.42"}`},
		{http.MethodPut, "/api/whitelist/order", `{"ids":[]}`},
		{http.MethodPatch, "/api/whitelist/203.0.113.42", `{"note":"updated"}`},
		{http.MethodDelete, "/api/whitelist/203.0.113.42", ``},
		{http.MethodPut, "/api/config/ports", `{"protectedPorts":"22"}`},
		{http.MethodGet, "/api/config/export", ``},
		{http.MethodPost, "/api/config/import", `{}`},
		{http.MethodPost, "/api/apply", `{}`},
		{http.MethodPost, "/api/restore", `{}`},
	} {
		req := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
		rec := httptest.NewRecorder()
		app.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s %s status = %d, want 401", tc.method, tc.path, rec.Code)
		}
	}
	if cfCalled {
		t.Fatal("unauthenticated Cloudflare sync reached fetch function")
	}
}

func TestParseCloudflareIPList(t *testing.T) {
	ranges, err := parseCloudflareIPList("https://example.test/ips-v4", strings.NewReader("\n# comment\n198.51.100.42/24\n203.0.113.0/24\n"))
	if err != nil {
		t.Fatalf("parseCloudflareIPList() error = %v", err)
	}
	want := []string{"198.51.100.0/24", "203.0.113.0/24"}
	if !reflect.DeepEqual(ranges, want) {
		t.Fatalf("parseCloudflareIPList() = %#v, want %#v", ranges, want)
	}
}

func TestParseCloudflareIPListRejectsIPv6(t *testing.T) {
	_, err := parseCloudflareIPList("https://example.test/ips-v4", strings.NewReader("2001:db8::/32\n"))
	if err == nil || !strings.Contains(err.Error(), "IPv6 is not supported") {
		t.Fatalf("parseCloudflareIPList() error = %v, want IPv6 rejection", err)
	}
}

func TestCloudflareHTTPClientRejectsRedirectOutsideCloudflare(t *testing.T) {
	client := cloudflareHTTPClient()
	req := httptest.NewRequest(http.MethodGet, "http://169.254.169.254/latest/meta-data", nil)
	if err := client.CheckRedirect(req, nil); err == nil {
		t.Fatal("CheckRedirect() error = nil, want non-Cloudflare redirect rejection")
	}

	req = httptest.NewRequest(http.MethodGet, "https://www.cloudflare.com/ips-v4/", nil)
	if err := client.CheckRedirect(req, nil); err != nil {
		t.Fatalf("CheckRedirect() Cloudflare URL error = %v", err)
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

	portsReq := httptest.NewRequest(http.MethodPut, "/api/config/ports", strings.NewReader(`{"protectedPorts":"8082,8008,8080-8081"}`))
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
	if body.Raw != "8008,8080-8082" || len(body.ProtectedPorts) != 4 || body.ProtectedPorts[0] != 8008 || body.ProtectedPorts[3] != 8082 {
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
