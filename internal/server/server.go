package server

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
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

type Firewall interface {
	Apply(context.Context, []int, []store.Entry) error
	Restore(context.Context) error
	Status(context.Context) string
}

type AppConfig struct {
	Config  config.Config
	Store   *store.Store
	Wall    Firewall
	Static  http.Handler
	Version string
}

type App struct {
	cfg      config.Config
	store    *store.Store
	wall     Firewall
	static   http.Handler
	version  string
	mux      *http.ServeMux
	sessions map[string]time.Time
	mu       sync.Mutex
}

func New(cfg AppConfig) *App {
	app := &App{
		cfg:      cfg.Config,
		store:    cfg.Store,
		wall:     cfg.Wall,
		static:   cfg.Static,
		version:  cfg.Version,
		mux:      http.NewServeMux(),
		sessions: map[string]time.Time{},
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
	a.mux.HandleFunc("POST /api/whitelist", a.withAuth(a.handleAddManual))
	a.mux.HandleFunc("PATCH /api/whitelist/{id}", a.withAuth(a.handleUpdateNote))
	a.mux.HandleFunc("DELETE /api/whitelist/{id}", a.withAuth(a.handleDelete))
	a.mux.HandleFunc("PUT /api/config/ports", a.withAuth(a.handleUpdatePorts))
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
	if !a.cfg.VerifyPassword(strings.TrimSpace(body.Username), body.Password) {
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
		"currentIP":         currentIP(r, a.cfg.TrustProxy),
		"entries":           a.store.List(),
		"protectedPorts":    a.cfg.ProtectedPorts,
		"protectedPortsRaw": a.cfg.ProtectedPortsRaw,
		"firewallStatus":    status,
		"firewallState":     state,
		"version":           a.version,
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
	var body struct {
		Note string `json:"note"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil && !errors.Is(err, http.ErrBodyNotAllowed) {
		writeError(w, http.StatusBadRequest, "请求体不是有效 JSON")
		return
	}
	ip, err := firewall.NormalizeIP(currentIP(r, a.cfg.TrustProxy))
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
	ip, err := firewall.NormalizeIP(body.IP)
	if err != nil {
		writeError(w, http.StatusBadRequest, "请输入单个有效 IP 地址")
		return
	}
	entry, err := a.store.AddOrUpdate(ip, body.Note)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, entry)
}

func (a *App) handleDelete(w http.ResponseWriter, r *http.Request) {
	if err := a.store.Delete(r.PathValue("id")); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
	raw := strings.TrimSpace(body.ProtectedPorts)
	if err := a.store.UpdateProtectedPorts(raw); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	a.cfg.ProtectedPorts = ports
	a.cfg.ProtectedPortsRaw = raw
	writeJSON(w, http.StatusOK, map[string]any{
		"protectedPorts":    ports,
		"protectedPortsRaw": raw,
	})
}

func (a *App) handleApply(w http.ResponseWriter, r *http.Request) {
	if a.wall == nil {
		writeError(w, http.StatusServiceUnavailable, "防火墙后端不可用")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	if err := a.wall.Apply(ctx, a.cfg.ProtectedPorts, a.store.List()); err != nil {
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
