package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadCreatesConfigFileWithHashedGeneratedPassword(t *testing.T) {
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
			Username:           "root",
			PasswordHash:       hash.PasswordHash,
			PasswordSalt:       hash.PasswordSalt,
			PasswordIterations: hash.PasswordIterations,
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
	if strings.Contains(string(data), "manual-secret") || strings.Contains(string(data), `"password"`) {
		t.Fatalf("config still contains plaintext password: %s", string(data))
	}
	if !strings.Contains(string(data), `"passwordHash"`) {
		t.Fatalf("config missing passwordHash after migration: %s", string(data))
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
			Username:           "admin",
			PasswordHash:       hash.PasswordHash,
			PasswordSalt:       hash.PasswordSalt,
			PasswordIterations: hash.PasswordIterations,
		},
	})
	t.Setenv("IPSETS_CONFIG_FILE", path)

	_, err = Load()
	if err == nil {
		t.Fatal("Load() error = nil, want invalid port error")
	}
}

func TestLoadAcceptsLegacyIPGuardEnvironmentOverrides(t *testing.T) {
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
