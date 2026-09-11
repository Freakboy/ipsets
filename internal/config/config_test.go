package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCreatesConfigFileWithHashedGeneratedPassword(t *testing.T) {
	originalDiscover := discoverPublicIPv4
	discoverPublicIPv4 = func() (netip.Addr, error) {
		return netip.MustParseAddr("198.51.100.42"), nil
	}
	defer func() { discoverPublicIPv4 = originalDiscover }()

	dir := t.TempDir()
	oldwd, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd() error = %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir() error = %v", err)
	}
	defer func() {
		if err := os.Chdir(oldwd); err != nil {
			t.Fatalf("restore Chdir() error = %v", err)
		}
	}()

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ListenAddr != ":8008" {
		t.Fatalf("ListenAddr = %q, want :8008", cfg.ListenAddr)
	}
	if cfg.TableName != "ipsets" {
		t.Fatalf("TableName = %q, want ipsets", cfg.TableName)
	}
	if cfg.ConfigPath != "config.json" {
		t.Fatalf("ConfigPath = %q, want config.json", cfg.ConfigPath)
	}
	if cfg.AdminUsername != "admin" {
		t.Fatalf("AdminUsername = %q, want admin", cfg.AdminUsername)
	}
	if cfg.InitialPassword == "" {
		t.Fatal("InitialPassword is empty, want generated password")
	}
	if !cfg.VerifyPassword("admin", cfg.InitialPassword) {
		t.Fatal("VerifyPassword(admin, InitialPassword) = false, want true")
	}

	data, err := os.ReadFile(cfg.ConfigPath)
	if err != nil {
		t.Fatalf("ReadFile(config) error = %v", err)
	}
	if string(data) == "" || json.Valid(data) == false {
		t.Fatalf("config file is not valid JSON: %q", string(data))
	}
	if contains := string(data); contains == cfg.InitialPassword {
		t.Fatal("config file contains plaintext initial password")
	}
	if !strings.Contains(string(data), `"password": "$2`) || strings.Contains(string(data), `"passwordHash"`) {
		t.Fatalf("config does not contain a single bcrypt password field: %s", data)
	}
	if !strings.Contains(string(data), `"ip": "198.51.100.0/24"`) {
		t.Fatalf("config missing discovered VPS public IPv4 /24: %s", data)
	}
}

func TestLoadReadsPortsAndCredentialsFromConfigFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	hash, err := HashPassword("s3cret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	writeTestConfig(t, path, DiskConfig{
		ListenAddr:     ":9000",
		TableName:      "custom_sets",
		ProtectedPorts: "22,8008,8080-8082",
		Admin: AdminConfig{
			Username: "root",
			Password: hash.PasswordHash,
		},
	})
	t.Setenv("IPSETS_CONFIG_FILE", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ListenAddr != ":9000" || cfg.TableName != "custom_sets" {
		t.Fatalf("config not loaded: %#v", cfg)
	}
	want := []int{22, 8008, 8080, 8081, 8082}
	if len(cfg.ProtectedPorts) != len(want) {
		t.Fatalf("ProtectedPorts = %#v, want %#v", cfg.ProtectedPorts, want)
	}
	for i := range want {
		if cfg.ProtectedPorts[i] != want[i] {
			t.Fatalf("ProtectedPorts = %#v, want %#v", cfg.ProtectedPorts, want)
		}
	}
	if !cfg.VerifyPassword("root", "s3cret") {
		t.Fatal("VerifyPassword(root, s3cret) = false, want true")
	}
	if cfg.VerifyPassword("root", "wrong") || cfg.VerifyPassword("admin", "s3cret") {
		t.Fatal("VerifyPassword accepted wrong credentials")
	}
}

func TestLoadHashesPlaintextPasswordFromConfigFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeTestConfig(t, path, DiskConfig{
		ProtectedPorts: "22",
		Admin: AdminConfig{
			Username: "ops",
			Password: "manual-secret",
		},
	})
	t.Setenv("IPSETS_CONFIG_FILE", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if !cfg.VerifyPassword("ops", "manual-secret") {
		t.Fatal("VerifyPassword(ops, manual-secret) = false, want true")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(config) error = %v", err)
	}
	if strings.Contains(string(data), "manual-secret") || !strings.Contains(string(data), `"password": "$2`) {
		t.Fatalf("config password was not replaced with bcrypt: %s", string(data))
	}
	if strings.Contains(string(data), `"passwordHash"`) || strings.Contains(string(data), `"passwordSalt"`) || strings.Contains(string(data), `"passwordIterations"`) {
		t.Fatalf("config still contains legacy password fields: %s", string(data))
	}
}

func TestLoadMigratesLegacyPBKDF2FieldsIntoSinglePasswordField(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	salt := base64.RawURLEncoding.EncodeToString([]byte("0123456789abcdef"))
	key, err := derivePassword("legacy-secret", salt, 210000)
	if err != nil {
		t.Fatalf("derivePassword() error = %v", err)
	}
	legacyHash := base64.RawURLEncoding.EncodeToString(key)
	data := fmt.Sprintf(`{"protectedPorts":"22","admin":{"username":"admin","passwordHash":%q,"passwordSalt":%q,"passwordIterations":210000},"whitelist":[]}`, legacyHash, salt)
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	t.Setenv("IPSETS_CONFIG_FILE", path)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.VerifyPassword("admin", "legacy-secret") {
		t.Fatal("legacy password no longer verifies after migration")
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(persisted), legacyPasswordPrefix) || strings.Contains(string(persisted), `"passwordHash"`) {
		t.Fatalf("legacy config was not migrated to one password field: %s", persisted)
	}
}

func TestLoadRejectsInvalidPorts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	hash, err := HashPassword("secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	writeTestConfig(t, path, DiskConfig{
		ProtectedPorts: "22,8090-8080",
		Admin: AdminConfig{
			Username: "admin",
			Password: hash.PasswordHash,
		},
	})
	t.Setenv("IPSETS_CONFIG_FILE", path)

	_, err = Load()
	if err == nil {
		t.Fatal("Load() error = nil, want invalid port error")
	}
}

func TestParseImportValidatesAndNormalizesConfig(t *testing.T) {
	hash, err := HashPassword("imported-secret")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	data, err := json.Marshal(DiskConfig{
		ListenAddr:     ":9000",
		TableName:      "imported_sets",
		ProtectedPorts: "443,80-81",
		TrustProxy:     true,
		Admin: AdminConfig{
			Username: "operator",
			Password: hash.PasswordHash,
		},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}

	cfg, err := ParseImport(data)
	if err != nil {
		t.Fatalf("ParseImport() error = %v", err)
	}
	if cfg.ListenAddr != ":9000" || cfg.TableName != "imported_sets" || cfg.ProtectedPortsRaw != "80-81,443" || !cfg.TrustProxy {
		t.Fatalf("ParseImport() = %#v, want normalized imported config", cfg)
	}
	if !cfg.VerifyPassword("operator", "imported-secret") {
		t.Fatal("imported config does not verify imported credentials")
	}
}

func TestParseImportHashesPlaintextAndRejectsInvalidEncodedHash(t *testing.T) {
	cfg, err := ParseImport([]byte(`{"protectedPorts":"22","admin":{"username":"admin","password":"secret"}}`))
	if err != nil {
		t.Fatalf("ParseImport(plaintext) error = %v", err)
	}
	if !strings.HasPrefix(cfg.AdminPasswordHash, "$2") || !cfg.VerifyPassword("admin", "secret") {
		t.Fatalf("ParseImport(plaintext) did not produce a usable bcrypt hash: %#v", cfg)
	}
	for _, data := range [][]byte{
		[]byte(`{"protectedPorts":"22","admin":{"username":"admin","password":"$2a$bad"}}`),
		[]byte(`{"protectedPorts":"22","admin":{"username":"admin","password":"$ipsets-pbkdf2$bad"}}`),
		[]byte(`[]`),
	} {
		if _, err := ParseImport(data); err == nil {
			t.Fatalf("ParseImport(%s) error = nil, want rejection", data)
		}
	}
}

func TestResetPasswordWritesBcryptAndPreservesConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(`{"custom":"kept","protectedPorts":"22","admin":{"username":"ops","password":"old"},"whitelist":[]}`), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := ResetPassword(path, "new-secret"); err != nil {
		t.Fatalf("ResetPassword() error = %v", err)
	}
	persisted, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if !strings.Contains(string(persisted), `"custom": "kept"`) || strings.Contains(string(persisted), "new-secret") || strings.Contains(string(persisted), `"passwordHash"`) {
		t.Fatalf("ResetPassword() persisted config = %s", persisted)
	}
	t.Setenv("IPSETS_CONFIG_FILE", path)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !cfg.VerifyPassword("ops", "new-secret") {
		t.Fatal("reset password does not verify")
	}
}

func TestCreateConfigContinuesWhenPublicIPLookupFails(t *testing.T) {
	originalDiscover := discoverPublicIPv4
	discoverPublicIPv4 = func() (netip.Addr, error) { return netip.Addr{}, errors.New("offline") }
	defer func() { discoverPublicIPv4 = originalDiscover }()
	path := filepath.Join(t.TempDir(), "config.json")
	disk, _, err := createDiskConfig(path)
	if err != nil {
		t.Fatalf("createDiskConfig() error = %v", err)
	}
	if len(disk.Whitelist) != 0 {
		t.Fatalf("Whitelist = %#v, want empty fallback when public IP lookup fails", disk.Whitelist)
	}
}

func TestParsePortsSortsAndFormatPortsCompactsRanges(t *testing.T) {
	ports, err := ParsePorts("8082,8008,8080-8081,22,8081")
	if err != nil {
		t.Fatalf("ParsePorts() error = %v", err)
	}
	want := []int{22, 8008, 8080, 8081, 8082}
	if len(ports) != len(want) {
		t.Fatalf("ParsePorts() = %#v, want %#v", ports, want)
	}
	for i := range want {
		if ports[i] != want[i] {
			t.Fatalf("ParsePorts() = %#v, want %#v", ports, want)
		}
	}
	if got := FormatPorts(ports); got != "22,8008,8080-8082" {
		t.Fatalf("FormatPorts() = %q, want sorted compact ranges", got)
	}
}

func TestLoadAcceptsLegacyIPGuardEnvironmentOverrides(t *testing.T) {
	originalDiscover := discoverPublicIPv4
	discoverPublicIPv4 = func() (netip.Addr, error) { return netip.Addr{}, errors.New("offline") }
	defer func() { discoverPublicIPv4 = originalDiscover }()
	legacyDir := t.TempDir()
	t.Setenv("IPGUARD_LISTEN", ":9090")
	t.Setenv("IPGUARD_DATA_DIR", legacyDir)
	t.Setenv("IPGUARD_CONFIG_FILE", filepath.Join(legacyDir, "config.json"))
	t.Setenv("IPGUARD_TABLE", "legacy_table")
	t.Setenv("IPGUARD_PROTECTED_PORTS", "443")
	t.Setenv("IPGUARD_TRUST_PROXY", "1")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ListenAddr != ":9090" || cfg.DataDir != legacyDir || cfg.TableName != "legacy_table" {
		t.Fatalf("legacy config not loaded: %#v", cfg)
	}
	if len(cfg.ProtectedPorts) != 1 || cfg.ProtectedPorts[0] != 443 {
		t.Fatalf("ProtectedPorts = %#v, want [443]", cfg.ProtectedPorts)
	}
	if !cfg.TrustProxy {
		t.Fatalf("TrustProxy = false, want true: %#v", cfg)
	}
}

func writeTestConfig(t *testing.T, path string, cfg DiskConfig) {
	t.Helper()
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent() error = %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
}
