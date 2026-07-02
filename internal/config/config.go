package config

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const passwordIterations = 210_000

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
	Username           string `json:"username"`
	Password           string `json:"password,omitempty"`
	PasswordHash       string `json:"passwordHash"`
	PasswordSalt       string `json:"passwordSalt"`
	PasswordIterations int    `json:"passwordIterations"`
}

type PasswordHash struct {
	PasswordHash       string
	PasswordSalt       string
	PasswordIterations int
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

	return Config{
		ListenAddr:              disk.ListenAddr,
		DataDir:                 dataDir,
		ConfigPath:              configPath,
		ProtectedPorts:          ports,
		ProtectedPortsRaw:       disk.ProtectedPorts,
		AdminUsername:           disk.Admin.Username,
		AdminPasswordHash:       disk.Admin.PasswordHash,
		AdminPasswordSalt:       disk.Admin.PasswordSalt,
		AdminPasswordIterations: disk.Admin.PasswordIterations,
		TrustProxy:              disk.TrustProxy,
		TableName:               disk.TableName,
		InitialPassword:         initialPassword,
	}, nil
}

func (c Config) VerifyPassword(username, password string) bool {
	if username != c.AdminUsername || username == "" {
		return false
	}
	got, err := derivePassword(password, c.AdminPasswordSalt, c.AdminPasswordIterations)
	if err != nil {
		return false
	}
	want, err := base64.RawURLEncoding.DecodeString(c.AdminPasswordHash)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func HashPassword(password string) (PasswordHash, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return PasswordHash{}, err
	}
	key, err := pbkdf2.Key(sha256.New, password, salt, passwordIterations, 32)
	if err != nil {
		return PasswordHash{}, err
	}
	return PasswordHash{
		PasswordHash:       base64.RawURLEncoding.EncodeToString(key),
		PasswordSalt:       base64.RawURLEncoding.EncodeToString(salt),
		PasswordIterations: passwordIterations,
	}, nil
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
	if disk.Admin.Password != "" {
		hash, err := HashPassword(disk.Admin.Password)
		if err != nil {
			return DiskConfig{}, "", err
		}
		disk.Admin.Password = ""
		disk.Admin.PasswordHash = hash.PasswordHash
		disk.Admin.PasswordSalt = hash.PasswordSalt
		disk.Admin.PasswordIterations = hash.PasswordIterations
		if err := writeDiskConfig(path, disk); err != nil {
			return DiskConfig{}, "", err
		}
	}
	if disk.Admin.PasswordHash == "" || disk.Admin.PasswordSalt == "" || disk.Admin.PasswordIterations == 0 {
		return DiskConfig{}, "", errors.New("admin password hash is missing from config file")
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
			Username:           "admin",
			PasswordHash:       hash.PasswordHash,
			PasswordSalt:       hash.PasswordSalt,
			PasswordIterations: hash.PasswordIterations,
		},
		Whitelist: []any{},
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
	return ports, nil
}

func parsePort(raw string) (int, error) {
	raw = strings.TrimSpace(raw)
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid protected port %q", raw)
	}
	return port, nil
}
