package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"ipsets/internal/config"
	"ipsets/internal/firewall"
	"ipsets/internal/store"
)

const (
	cloudflareSource = "cloudflare"
	cloudflareNote   = "Cloudflare proxy IP range"
)

var cloudflareIPListURLs = []string{
	"https://www.cloudflare.com/ips-v4/",
}

type Firewall interface {
	Apply(context.Context, []int, []store.Entry) error
	Restore(context.Context) error
	Status(context.Context) string
}

type CloudflareRangesFunc func(context.Context) ([]string, error)

type AppConfig struct {
	Config           config.Config
	Store            *store.Store
	Wall             Firewall
	Static           http.Handler
	Version          string
	CloudflareRanges CloudflareRangesFunc
}

type App struct {
	cfg                  config.Config
	store                *store.Store
	wall                 Firewall
	static               http.Handler
	version              string
	cfRanges             CloudflareRangesFunc
	mux                  *http.ServeMux
	sessions             map[string]time.Time
	tableRestartRequired bool
	mu                   sync.Mutex
}

func New(cfg AppConfig) *App {
	app := &App{
		cfg:      cfg.Config,
		store:    cfg.Store,
		wall:     cfg.Wall,
		static:   cfg.Static,
		version:  cfg.Version,
		cfRanges: cfg.CloudflareRanges,
		mux:      http.NewServeMux(),
		sessions: map[string]time.Time{},
	}
	if app.cfRanges == nil {
		app.cfRanges = fetchCloudflareIPRanges
	}
	app.routes()
	return app
}

func (a *App) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	a.mux.ServeHTTP(w, r)
}

func (a *App) routes() {
	a.mux.HandleFunc("POST /api/login", a.handleLogin)
	a.mux.HandleFunc("POST /api/logout", a.withAuth(a.handleLogout))
	a.mux.HandleFunc("GET /api/state", a.withAuth(a.handleState))
	a.mux.HandleFunc("POST /api/whitelist/current", a.withAuth(a.handleAddCurrent))
	a.mux.HandleFunc("POST /api/whitelist/cloudflare", a.withAuth(a.handleSyncCloudflare))
	a.mux.HandleFunc("POST /api/whitelist", a.withAuth(a.handleAddManual))
	a.mux.HandleFunc("PATCH /api/whitelist/{id}", a.withAuth(a.handleUpdateNote))
	a.mux.HandleFunc("PUT /api/whitelist/order", a.withAuth(a.handleReorder))
	a.mux.HandleFunc("DELETE /api/whitelist/{id}", a.withAuth(a.handleDelete))
	a.mux.HandleFunc("PUT /api/config/ports", a.withAuth(a.handleUpdatePorts))
	a.mux.HandleFunc("GET /api/config/export", a.withAuth(a.handleExportConfig))
	a.mux.HandleFunc("POST /api/config/import", a.withAuth(a.handleImportConfig))
	a.mux.HandleFunc("POST /api/apply", a.withAuth(a.handleApply))
	a.mux.HandleFunc("POST /api/restore", a.withAuth(a.handleRestore))
	if a.static != nil {
		a.mux.Handle("/", a.static)
	}
}

func (a *App) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !a.validSession(r) {
			writeError(w, http.StatusUnauthorized, "需要管理员用户名和密码")
			return
		}
		next(w, r)
	}
}

func (a *App) handleLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	if !a.configSnapshot().VerifyPassword(strings.TrimSpace(body.Username), body.Password) {
		writeError(w, http.StatusUnauthorized, "用户名或密码不正确")
		return
	}

	token, err := randomSessionToken()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	expires := time.Now().Add(24 * time.Hour)
	a.mu.Lock()
	a.sessions[token] = expires
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name:     "ipsets_session",
		Value:    token,
		Path:     "/",
		Expires:  expires,
		MaxAge:   int((24 * time.Hour).Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) handleLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("ipsets_session"); err == nil {
		a.mu.Lock()
		delete(a.sessions, cookie.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "ipsets_session",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *App) validSession(r *http.Request) bool {
	cookie, err := r.Cookie("ipsets_session")
	if err != nil || cookie.Value == "" {
		return false
	}
	now := time.Now()
	a.mu.Lock()
	defer a.mu.Unlock()
	expires, ok := a.sessions[cookie.Value]
	if !ok {
		return false
	}
	if now.After(expires) {
		delete(a.sessions, cookie.Value)
		return false
	}
	return true
}

func randomSessionToken() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func (a *App) handleState(w http.ResponseWriter, r *http.Request) {
	cfg := a.configSnapshot()
	status := "unavailable"
	if a.wall != nil {
		ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
		defer cancel()
		status = a.wall.Status(ctx)
	}
	state, err := a.reconcileFirewallState(status)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"currentIP":         currentIP(r, cfg.TrustProxy),
		"entries":           a.store.List(),
		"protectedPorts":    cfg.ProtectedPorts,
		"protectedPortsRaw": cfg.ProtectedPortsRaw,
		"firewallStatus":    status,
		"firewallState":     state,
		"version":           a.version,
		"restartRequired":   a.restartRequired(),
	})
}

func (a *App) reconcileFirewallState(actual string) (store.FirewallState, error) {
	state := a.store.FirewallState()
	switch {
	case state.Status == "applied" && actual != "applied":
		state = store.FirewallState{
			Status:  "error",
			Message: "记录为已应用，但当前未检测到防火墙规则，请重新应用规则",
		}
	case state.Status == "restored" && actual == "applied":
		state = store.FirewallState{
			Status:  "error",
			Message: "记录为已恢复，但当前仍检测到防火墙规则，请恢复原始状态",
		}
	default:
		return state, nil
	}
	if err := a.store.UpdateFirewallState(state); err != nil {
		return store.FirewallState{}, err
	}
	return a.store.FirewallState(), nil
}

func (a *App) handleAddCurrent(w http.ResponseWriter, r *http.Request) {
	cfg := a.configSnapshot()
	var body struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, http.ErrBodyNotAllowed) {
		writeError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	ip, err := firewall.NormalizeIP(currentIP(r, cfg.TrustProxy))
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法识别当前访问 IP")
		return
	}
	entry, err := a.store.AddOrUpdate(ip, body.Note)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (a *App) handleAddManual(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP   string `json:"ip"`
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	address, err := firewall.NormalizeIPOrCIDR(body.IP)
	if err != nil {
		writeError(w, http.StatusBadRequest, "请输入有效 IP 地址或 CIDR 网段")
		return
	}
	entry, err := a.store.AddOrUpdateAddress(address.Value, body.Note)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (a *App) handleSyncCloudflare(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	ranges, err := a.cfRanges(ctx)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	ranges, err = normalizeCloudflareRanges(ranges)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	result, err := a.store.SyncSource(cloudflareSource, ranges, cloudflareNote)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"source":  cloudflareSource,
		"added":   result.Added,
		"updated": result.Updated,
		"removed": result.Removed,
		"entries": result.Entries,
	})
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Delete(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *App) handleReorder(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDs []string `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	if err := a.store.Reorder(body.IDs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": a.store.List()})
}

func (a *App) handleUpdateNote(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	entry, err := a.store.UpdateNote(r.PathValue("id"), body.Note)
	if errors.Is(err, os.ErrNotExist) {
		writeError(w, http.StatusNotFound, "白名单项不存在")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (a *App) handleUpdatePorts(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ProtectedPorts string `json:"protectedPorts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	ports, err := config.ParsePorts(body.ProtectedPorts)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	raw := config.FormatPorts(ports)
	if err := a.store.UpdateProtectedPorts(raw); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.mu.Lock()
	a.cfg.ProtectedPorts = ports
	a.cfg.ProtectedPortsRaw = raw
	a.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{
		"protectedPorts":    ports,
		"protectedPortsRaw": raw,
	})
}

func (a *App) handleExportConfig(w http.ResponseWriter, r *http.Request) {
	cfg := a.configSnapshot()
	data, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Disposition", `attachment; filename="ipsets-config.json"`)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (a *App) handleImportConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "配置文件不能超过 2 MiB")
			return
		}
		writeError(w, http.StatusBadRequest, "无法读取配置文件")
		return
	}
	importedCfg, err := config.ParseImport(data)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var imported struct {
		Whitelist []store.Entry `json:"whitelist"`
	}
	if err := json.Unmarshal(data, &imported); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	now := time.Now().UTC()
	seen := make(map[string]bool, len(imported.Whitelist))
	for i := range imported.Whitelist {
		address, err := firewall.NormalizeIPOrCIDR(imported.Whitelist[i].IP)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("无效的白名单地址 %q", imported.Whitelist[i].IP))
			return
		}
		if seen[address.Value] {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("白名单地址重复：%s", address.Value))
			return
		}
		seen[address.Value] = true
		imported.Whitelist[i].ID = address.Value
		imported.Whitelist[i].IP = address.Value
		imported.Whitelist[i].Order = i
		imported.Whitelist[i].Note = strings.TrimSpace(imported.Whitelist[i].Note)
		imported.Whitelist[i].Source = strings.TrimSpace(imported.Whitelist[i].Source)
		if imported.Whitelist[i].CreatedAt.IsZero() {
			imported.Whitelist[i].CreatedAt = now
		}
		if imported.Whitelist[i].UpdatedAt.IsZero() {
			imported.Whitelist[i].UpdatedAt = imported.Whitelist[i].CreatedAt
		}
	}
	if _, err := firewall.BuildNFTScript(firewall.NFTConfig{
		TableName: importedCfg.TableName,
		TCPPorts:  importedCfg.ProtectedPorts,
	}, imported.Whitelist); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	var persisted map[string]json.RawMessage
	if err := json.Unmarshal(data, &persisted); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	portsData, err := json.Marshal(importedCfg.ProtectedPortsRaw)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	persisted["protectedPorts"] = portsData
	adminData, err := json.Marshal(config.AdminConfig{
		Username: importedCfg.AdminUsername,
		Password: importedCfg.AdminPasswordHash,
	})
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	persisted["admin"] = adminData
	data, err = json.Marshal(persisted)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if err := a.store.ImportConfig(data, imported.Whitelist); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	a.mu.Lock()
	tableChanged := a.cfg.TableName != importedCfg.TableName
	restartRequired := a.cfg.ListenAddr != importedCfg.ListenAddr || tableChanged
	a.tableRestartRequired = tableChanged
	a.cfg.ProtectedPorts = importedCfg.ProtectedPorts
	a.cfg.ProtectedPortsRaw = importedCfg.ProtectedPortsRaw
	a.cfg.AdminUsername = importedCfg.AdminUsername
	a.cfg.AdminPasswordHash = importedCfg.AdminPasswordHash
	a.cfg.AdminPasswordSalt = importedCfg.AdminPasswordSalt
	a.cfg.AdminPasswordIterations = importedCfg.AdminPasswordIterations
	a.cfg.TrustProxy = importedCfg.TrustProxy
	a.mu.Unlock()

	message := "配置已导入，需要重新应用规则"
	if restartRequired {
		message = "配置已导入；监听地址或表名已变化，请重启 IPSets 后重新应用规则"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":         message,
		"restartRequired": restartRequired,
	})
}

func (a *App) handleApply(w http.ResponseWriter, r *http.Request) {
	if a.restartRequired() {
		writeError(w, http.StatusConflict, "配置中的 nftables 表名已变化，请重启 IPSets 后再应用规则")
		return
	}
	if a.wall == nil {
		writeError(w, http.StatusServiceUnavailable, "防火墙后端不可用")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.wall.Apply(ctx, a.configSnapshot().ProtectedPorts, a.store.List()); err != nil {
		_ = a.store.UpdateFirewallState(store.FirewallState{Status: "error", Message: err.Error()})
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	state := store.FirewallState{Status: "applied", Message: "规则已应用"}
	if err := a.store.UpdateFirewallState(state); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "applied", "firewallState": a.store.FirewallState()})
}

func (a *App) configSnapshot() config.Config {
	a.mu.Lock()
	defer a.mu.Unlock()
	cfg := a.cfg
	cfg.ProtectedPorts = append([]int(nil), a.cfg.ProtectedPorts...)
	return cfg
}

func (a *App) restartRequired() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.tableRestartRequired
}

func (a *App) handleRestore(w http.ResponseWriter, r *http.Request) {
	if a.wall == nil {
		writeError(w, http.StatusServiceUnavailable, "防火墙后端不可用")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.wall.Restore(ctx); err != nil {
		_ = a.store.UpdateFirewallState(store.FirewallState{Status: "error", Message: err.Error()})
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	state := store.FirewallState{Status: "restored", Message: "已恢复原始状态"}
	if err := a.store.UpdateFirewallState(state); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "restored", "firewallState": a.store.FirewallState()})
}

func currentIP(r *http.Request, trustProxy bool) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP, remoteErr := netip.ParseAddr(host)
	if trustProxy || (remoteErr == nil && remoteIP.IsLoopback()) {
		if ip, ok := forwardedClientIP(r); ok {
			return ip.String()
		}
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Unmap().String()
	}
	return host
}

func fetchCloudflareIPRanges(ctx context.Context) ([]string, error) {
	client := cloudflareHTTPClient()
	var ranges []string
	for _, url := range cloudflareIPListURLs {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", "ipsets")
		resp, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("fetch Cloudflare IP list %s: %w", url, err)
		}
		if resp.StatusCode != http.StatusOK {
			_ = resp.Body.Close()
			return nil, fmt.Errorf("fetch Cloudflare IP list %s: HTTP %d", url, resp.StatusCode)
		}
		parsed, err := parseCloudflareIPList(url, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			return nil, err
		}
		ranges = append(ranges, parsed...)
	}
	return ranges, nil
}

func cloudflareHTTPClient() http.Client {
	return http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many Cloudflare IP list redirects")
			}
			if req.URL.Scheme != "https" || !strings.EqualFold(req.URL.Host, "www.cloudflare.com") {
				return fmt.Errorf("refusing Cloudflare IP list redirect to %s", req.URL.String())
			}
			return nil
		},
	}
}

func normalizeCloudflareRanges(values []string) ([]string, error) {
	ranges := make([]string, 0, len(values))
	seen := map[string]bool{}
	for _, value := range values {
		address, err := firewall.NormalizeIPOrCIDR(value)
		if err != nil {
			return nil, fmt.Errorf("invalid Cloudflare IP range %q: %w", value, err)
		}
		if !address.Is4 {
			return nil, fmt.Errorf("invalid Cloudflare IP range %q: IPv6 is not supported", value)
		}
		if !strings.Contains(address.Value, "/") {
			return nil, fmt.Errorf("invalid Cloudflare IP range %q is not CIDR", value)
		}
		if !seen[address.Value] {
			ranges = append(ranges, address.Value)
			seen[address.Value] = true
		}
	}
	if len(ranges) == 0 {
		return nil, errors.New("Cloudflare IP range list is empty")
	}
	return ranges, nil
}

func parseCloudflareIPList(source string, r io.Reader) ([]string, error) {
	var ranges []string
	seen := map[string]bool{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		address, err := firewall.NormalizeIPOrCIDR(line)
		if err != nil {
			return nil, fmt.Errorf("invalid Cloudflare IP range from %s: %q: %w", source, line, err)
		}
		if !address.Is4 {
			return nil, fmt.Errorf("invalid Cloudflare IP range from %s: %q: IPv6 is not supported", source, line)
		}
		if !strings.Contains(address.Value, "/") {
			return nil, fmt.Errorf("invalid Cloudflare IP range from %s: %q is not CIDR", source, line)
		}
		if !seen[address.Value] {
			ranges = append(ranges, address.Value)
			seen[address.Value] = true
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read Cloudflare IP list %s: %w", source, err)
	}
	if len(ranges) == 0 {
		return nil, fmt.Errorf("Cloudflare IP list %s is empty", source)
	}
	return ranges, nil
}

func forwardedClientIP(r *http.Request) (netip.Addr, bool) {
	for _, value := range r.Header.Values("Forwarded") {
		if ip, ok := parseForwardedHeader(value); ok {
			return ip, true
		}
	}
	for _, name := range []string{"CF-Connecting-IP", "X-Real-IP", "X-Forwarded-For"} {
		if ip, ok := parseIPHeader(r.Header.Get(name)); ok {
			return ip, true
		}
	}
	return netip.Addr{}, false
}

func parseForwardedHeader(value string) (netip.Addr, bool) {
	for _, part := range strings.Split(value, ",") {
		for _, pair := range strings.Split(part, ";") {
			key, raw, found := strings.Cut(strings.TrimSpace(pair), "=")
			if !found || !strings.EqualFold(strings.TrimSpace(key), "for") {
				continue
			}
			if ip, ok := parseIPHeader(raw); ok {
				return ip, true
			}
		}
	}
	return netip.Addr{}, false
}

func parseIPHeader(value string) (netip.Addr, bool) {
	for _, part := range strings.Split(value, ",") {
		part = strings.Trim(strings.TrimSpace(part), `"`)
		part = strings.TrimPrefix(part, "[")
		part = strings.TrimSuffix(part, "]")
		if host, _, err := net.SplitHostPort(part); err == nil {
			part = host
		}
		if ip, err := netip.ParseAddr(part); err == nil {
			return ip.Unmap(), true
		}
	}
	return netip.Addr{}, false
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
