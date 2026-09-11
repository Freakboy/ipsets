package config

import (
	"bufio"
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const legacyPasswordPrefix = "$ipsets-pbkdf2$"

var discoverPublicIPv4 = fetchPublicIPv4

type Config struct {
	ListenAddr              string
	DataDir                 string
	ConfigPath              string
	ProtectedPorts          []int
	ProtectedPortsRaw       string
	AdminUsername           string
	AdminPasswordHash       string
	AdminPasswordSalt       string
	AdminPasswordIterations int
	TrustProxy              bool
	TableName               string
	InitialPassword         string
}

type DiskConfig struct {
	ListenAddr     string      `json:"listenAddr"`
	TableName      string      `json:"tableName"`
	ProtectedPorts string      `json:"protectedPorts"`
	TrustProxy     bool        `json:"trustProxy"`
	Admin          AdminConfig `json:"admin"`
	Whitelist      []any       `json:"whitelist"`
}

type AdminConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`

	legacyHash       string
	legacySalt       string
	legacyIterations int
}

func (a AdminConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}{Username: a.Username, Password: a.Password})
}

type PasswordHash struct {
	PasswordHash       string
	PasswordSalt       string
	PasswordIterations int
}

func (a *AdminConfig) UnmarshalJSON(data []byte) error {
	var raw struct {
		Username           string `json:"username"`
		Password           string `json:"password"`
		PasswordHash       string `json:"passwordHash"`
		PasswordSalt       string `json:"passwordSalt"`
		PasswordIterations int    `json:"passwordIterations"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	a.Username = raw.Username
	a.Password = raw.Password
	a.legacyHash = raw.PasswordHash
	a.legacySalt = raw.PasswordSalt
	a.legacyIterations = raw.PasswordIterations
	return nil
}

func Load() (Config, error) {
	dataDir := env("DATA_DIR")
	if dataDir == "" {
		dataDir = "./data"
	}
	configPath := env("CONFIG_FILE")
	if configPath == "" {
		configPath = "config.json"
	}

	disk, initialPassword, err := loadDiskConfig(configPath)
	if err != nil {
		return Config{}, err
	}

	if value := env("LISTEN"); value != "" {
		disk.ListenAddr = value
	}
	if value := env("TABLE"); value != "" {
		disk.TableName = value
	}
	if value := env("PROTECTED_PORTS"); value != "" {
		disk.ProtectedPorts = value
	}
	if value := env("TRUST_PROXY"); value != "" {
		disk.TrustProxy = strings.EqualFold(value, "true") || value == "1"
	}

	ports, err := ParsePorts(disk.ProtectedPorts)
	if err != nil {
		return Config{}, err
	}
	if _, err := net.ResolveTCPAddr("tcp", disk.ListenAddr); err != nil {
		return Config{}, fmt.Errorf("invalid listen address %q: %w", disk.ListenAddr, err)
	}

	return Config{
		ListenAddr:        disk.ListenAddr,
		DataDir:           dataDir,
		ConfigPath:        configPath,
		ProtectedPorts:    ports,
		ProtectedPortsRaw: disk.ProtectedPorts,
		AdminUsername:     disk.Admin.Username,
		AdminPasswordHash: disk.Admin.Password,
		TrustProxy:        disk.TrustProxy,
		TableName:         disk.TableName,
		InitialPassword:   initialPassword,
	}, nil
}

func ParseImport(data []byte) (Config, error) {
	trimmed := strings.TrimSpace(string(data))
	if !strings.HasPrefix(trimmed, "{") || !json.Valid(data) {
		return Config{}, errors.New("imported config must be a JSON object")
	}

	var disk DiskConfig
	if err := json.Unmarshal(data, &disk); err != nil {
		return Config{}, err
	}
	applyDiskDefaults(&disk)
	if _, err := normalizeAdminPassword(&disk.Admin); err != nil {
		return Config{}, err
	}
	ports, err := ParsePorts(disk.ProtectedPorts)
	if err != nil {
		return Config{}, err
	}
	if _, err := net.ResolveTCPAddr("tcp", disk.ListenAddr); err != nil {
		return Config{}, fmt.Errorf("invalid listen address %q: %w", disk.ListenAddr, err)
	}

	return Config{
		ListenAddr:        disk.ListenAddr,
		ProtectedPorts:    ports,
		ProtectedPortsRaw: FormatPorts(ports),
		AdminUsername:     disk.Admin.Username,
		AdminPasswordHash: disk.Admin.Password,
		TrustProxy:        disk.TrustProxy,
		TableName:         disk.TableName,
	}, nil
}

func (c Config) VerifyPassword(username, password string) bool {
	if username != c.AdminUsername || username == "" {
		return false
	}
	if strings.HasPrefix(c.AdminPasswordHash, legacyPasswordPrefix) {
		return verifyLegacyPassword(c.AdminPasswordHash, password)
	}
	return bcrypt.CompareHashAndPassword([]byte(c.AdminPasswordHash), []byte(password)) == nil
}

func HashPassword(password string) (PasswordHash, error) {
	if password == "" {
		return PasswordHash{}, errors.New("password cannot be empty")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return PasswordHash{}, err
	}
	return PasswordHash{PasswordHash: string(hash)}, nil
}

func loadDiskConfig(path string) (DiskConfig, string, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return createDiskConfig(path)
	}
	if err != nil {
		return DiskConfig{}, "", err
	}

	var disk DiskConfig
	if err := json.Unmarshal(data, &disk); err != nil {
		return DiskConfig{}, "", err
	}
	applyDiskDefaults(&disk)
	changed, err := normalizeAdminPassword(&disk.Admin)
	if err != nil {
		return DiskConfig{}, "", err
	}
	if changed {
		if err := writeAdminConfig(path, data, disk.Admin); err != nil {
			return DiskConfig{}, "", err
		}
	}
	return disk, "", nil
}

func createDiskConfig(path string) (DiskConfig, string, error) {
	password, err := randomPassword()
	if err != nil {
		return DiskConfig{}, "", err
	}
	hash, err := HashPassword(password)
	if err != nil {
		return DiskConfig{}, "", err
	}
	disk := DiskConfig{
		ListenAddr:     ":8008",
		TableName:      "ipsets",
		ProtectedPorts: "22",
		TrustProxy:     false,
		Admin: AdminConfig{
			Username: "admin",
			Password: hash.PasswordHash,
		},
		Whitelist: []any{},
	}
	if ip, err := discoverPublicIPv4(); err == nil {
		prefix := netip.PrefixFrom(ip, 24).Masked().String()
		now := time.Now().UTC()
		disk.Whitelist = []any{map[string]any{
			"id":        prefix,
			"ip":        prefix,
			"order":     0,
			"note":      "VPS public IPv4 /24",
			"createdAt": now,
			"updatedAt": now,
		}}
	}
	if err := writeDiskConfig(path, disk); err != nil {
		return DiskConfig{}, "", err
	}
	return disk, password, nil
}

func writeDiskConfig(path string, disk DiskConfig) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(disk, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func applyDiskDefaults(disk *DiskConfig) {
	if disk.ListenAddr == "" {
		disk.ListenAddr = ":8008"
	}
	if disk.TableName == "" {
		disk.TableName = "ipsets"
	}
	if disk.ProtectedPorts == "" {
		disk.ProtectedPorts = "22"
	}
	if disk.Admin.Username == "" {
		disk.Admin.Username = "admin"
	}
	if disk.Whitelist == nil {
		disk.Whitelist = []any{}
	}
}

func randomPassword() (string, error) {
	raw := make([]byte, 18)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func derivePassword(password, saltRaw string, iterations int) ([]byte, error) {
	if iterations <= 0 {
		return nil, errors.New("password iterations must be positive")
	}
	salt, err := base64.RawURLEncoding.DecodeString(saltRaw)
	if err != nil {
		return nil, err
	}
	return pbkdf2.Key(sha256.New, password, salt, iterations, 32)
}

func normalizeAdminPassword(admin *AdminConfig) (bool, error) {
	if admin.Password == "" && admin.legacyHash != "" && admin.legacySalt != "" && admin.legacyIterations > 0 {
		admin.Password = fmt.Sprintf("%s%d$%s$%s", legacyPasswordPrefix, admin.legacyIterations, admin.legacySalt, admin.legacyHash)
		return true, nil
	}
	if admin.Password == "" {
		return false, errors.New("admin password is missing from config file")
	}
	if strings.HasPrefix(admin.Password, "$2a$") || strings.HasPrefix(admin.Password, "$2b$") || strings.HasPrefix(admin.Password, "$2y$") {
		if _, err := bcrypt.Cost([]byte(admin.Password)); err != nil {
			return false, errors.New("admin bcrypt password hash is invalid")
		}
		return false, nil
	}
	if strings.HasPrefix(admin.Password, legacyPasswordPrefix) {
		if !validLegacyPassword(admin.Password) {
			return false, errors.New("legacy admin password hash is invalid")
		}
		return false, nil
	}
	hash, err := HashPassword(admin.Password)
	if err != nil {
		return false, err
	}
	admin.Password = hash.PasswordHash
	return true, nil
}

func validLegacyPassword(encoded string) bool {
	parts := strings.Split(strings.TrimPrefix(encoded, legacyPasswordPrefix), "$")
	if len(parts) != 3 {
		return false
	}
	iterations, err := strconv.Atoi(parts[0])
	if err != nil || iterations <= 0 {
		return false
	}
	salt, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || len(salt) == 0 {
		return false
	}
	hash, err := base64.RawURLEncoding.DecodeString(parts[2])
	return err == nil && len(hash) == 32
}

func verifyLegacyPassword(encoded, password string) bool {
	if !validLegacyPassword(encoded) {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(encoded, legacyPasswordPrefix), "$")
	iterations, _ := strconv.Atoi(parts[0])
	got, err := derivePassword(password, parts[1], iterations)
	if err != nil {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(parts[2])
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

func writeAdminConfig(path string, data []byte, admin AdminConfig) error {
	raw := map[string]json.RawMessage{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	adminData, err := json.Marshal(admin)
	if err != nil {
		return err
	}
	raw["admin"] = adminData
	return writeRawConfig(path, raw)
}

func ResetPassword(path, password string) error {
	hash, err := HashPassword(password)
	if err != nil {
		return err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var disk DiskConfig
	if err := json.Unmarshal(data, &disk); err != nil {
		return err
	}
	applyDiskDefaults(&disk)
	disk.Admin.Password = hash.PasswordHash
	return writeAdminConfig(path, data, disk.Admin)
}

func writeRawConfig(path string, raw map[string]json.RawMessage) error {
	data, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func fetchPublicIPv4() (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api4.ipify.org", nil)
	if err != nil {
		return netip.Addr{}, err
	}
	req.Header.Set("User-Agent", "ipsets")
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return netip.Addr{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return netip.Addr{}, fmt.Errorf("public IP lookup returned HTTP %d", resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	if !scanner.Scan() {
		return netip.Addr{}, errors.New("public IP lookup returned an empty response")
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(scanner.Text()))
	if err != nil || !ip.Is4() {
		return netip.Addr{}, errors.New("public IP lookup did not return an IPv4 address")
	}
	return ip, nil
}

func env(name string) string {
	if value := strings.TrimSpace(os.Getenv("IPSETS_" + name)); value != "" {
		return value
	}
	return strings.TrimSpace(os.Getenv("IPGUARD_" + name))
}

func ParsePorts(raw string) ([]int, error) {
	parts := strings.Split(raw, ",")
	ports := make([]int, 0, len(parts))
	seen := map[int]bool{}
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		startRaw, endRaw, isRange := strings.Cut(part, "-")
		if !isRange {
			port, err := parsePort(part)
			if err != nil {
				return nil, err
			}
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
			continue
		}

		start, err := parsePort(startRaw)
		if err != nil {
			return nil, err
		}
		end, err := parsePort(endRaw)
		if err != nil {
			return nil, err
		}
		if start > end {
			return nil, fmt.Errorf("invalid protected port range %q", part)
		}
		for port := start; port <= end; port++ {
			if !seen[port] {
				ports = append(ports, port)
				seen[port] = true
			}
		}
	}
	if len(ports) == 0 {
		return nil, errors.New("at least one protected port is required")
	}
	sort.Ints(ports)
	return ports, nil
}

func FormatPorts(ports []int) string {
	if len(ports) == 0 {
		return ""
	}
	values := append([]int(nil), ports...)
	sort.Ints(values)

	ranges := make([]string, 0, len(values))
	start := values[0]
	prev := values[0]
	for i := 1; i < len(values); i++ {
		port := values[i]
		if port == prev {
			continue
		}
		if port == prev+1 {
			prev = port
			continue
		}
		ranges = append(ranges, formatPortRange(start, prev))
		start = port
		prev = port
	}
	ranges = append(ranges, formatPortRange(start, prev))
	return strings.Join(ranges, ",")
}

func formatPortRange(start, end int) string {
	if start == end {
		return strconv.Itoa(start)
	}
	return strconv.Itoa(start) + "-" + strconv.Itoa(end)
}

func parsePort(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid protected port %q", raw)
	}
	return port, nil
}
