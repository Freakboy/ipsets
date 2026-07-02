package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"ipsets/internal/store"
)

type NFTConfig struct {
	TableName string
	TCPPorts  []int
	DataDir   string
}

type NFTManager struct {
	cfg NFTConfig
}

func NewNFTManager(cfg NFTConfig) *NFTManager {
	return &NFTManager{cfg: cfg}
}

func NormalizeIP(raw string) (netip.Addr, error) {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "/") {
		return netip.Addr{}, fmt.Errorf("CIDR ranges are not supported: %s", raw)
	}
	ip, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, err
	}
	return ip.Unmap(), nil
}

func BuildNFTScript(cfg NFTConfig, entries []store.Entry) (string, error) {
	table := strings.TrimSpace(cfg.TableName)
	if table == "" {
		table = "ipsets"
	}
	if len(cfg.TCPPorts) == 0 {
		return "", errors.New("at least one TCP port is required")
	}

	var v4 []string
	var v6 []string
	for _, entry := range entries {
		ip, err := NormalizeIP(entry.IP)
		if err != nil {
			return "", fmt.Errorf("invalid whitelist IP %q: %w", entry.IP, err)
		}
		if ip.Is4() {
			v4 = append(v4, ip.String())
		} else {
			v6 = append(v6, ip.String())
		}
	}

	portSet := formatPorts(cfg.TCPPorts)
	var b strings.Builder
	fmt.Fprintf(&b, "table inet %s {\n", table)
	writeNFTSet(&b, "whitelist_v4", "ipv4_addr", v4)
	writeNFTSet(&b, "whitelist_v6", "ipv6_addr", v6)
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type filter hook prerouting priority -101; policy accept;\n")
	b.WriteString("    iifname \"lo\" accept\n")
	fmt.Fprintf(&b, "    fib daddr type local tcp dport %s ip saddr @whitelist_v4 accept\n", portSet)
	fmt.Fprintf(&b, "    fib daddr type local tcp dport %s ip6 saddr @whitelist_v6 accept\n", portSet)
	fmt.Fprintf(&b, "    fib daddr type local tcp dport %s drop\n", portSet)
	b.WriteString("  }\n")
	b.WriteString("  chain input {\n")
	b.WriteString("    type filter hook input priority filter; policy accept;\n")
	b.WriteString("    ct state established,related accept\n")
	b.WriteString("    iifname \"lo\" accept\n")
	fmt.Fprintf(&b, "    tcp dport %s ip saddr @whitelist_v4 accept\n", portSet)
	fmt.Fprintf(&b, "    tcp dport %s ip6 saddr @whitelist_v6 accept\n", portSet)
	fmt.Fprintf(&b, "    tcp dport %s drop\n", portSet)
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

func writeNFTSet(b *strings.Builder, name, setType string, elements []string) {
	fmt.Fprintf(b, "  set %s {\n", name)
	fmt.Fprintf(b, "    type %s\n", setType)
	if len(elements) > 0 {
		fmt.Fprintf(b, "    elements = { %s }\n", strings.Join(elements, ", "))
	}
	b.WriteString("  }\n")
}

func (m *NFTManager) Apply(ctx context.Context, ports []int, entries []store.Entry) error {
	if err := m.backupOriginal(ctx); err != nil {
		return err
	}
	cfg := m.cfg
	cfg.TCPPorts = append([]int(nil), ports...)
	script, err := BuildNFTScript(cfg, entries)
	if err != nil {
		return err
	}

	_ = exec.CommandContext(ctx, "nft", "delete", "table", "inet", m.tableName()).Run()
	file, err := os.CreateTemp("", "ipsets-*.nft")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.WriteString(script); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	output, err := exec.CommandContext(ctx, "nft", "-f", file.Name()).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m *NFTManager) Restore(ctx context.Context) error {
	output, err := exec.CommandContext(ctx, "nft", "delete", "table", "inet", m.tableName()).CombinedOutput()
	if err != nil && !strings.Contains(string(output), "No such file or directory") && !strings.Contains(string(output), "No such table") {
		return fmt.Errorf("nft restore failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m *NFTManager) Status(ctx context.Context) string {
	err := exec.CommandContext(ctx, "nft", "list", "table", "inet", m.tableName()).Run()
	if err != nil {
		return "not_applied"
	}
	return "applied"
}

func (m *NFTManager) backupOriginal(ctx context.Context) error {
	if strings.TrimSpace(m.cfg.DataDir) == "" {
		return nil
	}
	if err := os.MkdirAll(m.cfg.DataDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(m.cfg.DataDir, "original-ruleset.nft")
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	output, err := exec.CommandContext(ctx, "nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft backup failed: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return os.WriteFile(path, output, 0o600)
}

func (m *NFTManager) tableName() string {
	if strings.TrimSpace(m.cfg.TableName) == "" {
		return "ipsets"
	}
	return m.cfg.TableName
}

func formatPorts(ports []int) string {
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}
	if len(values) == 1 {
		return values[0]
	}
	return "{ " + strings.Join(values, ", ") + " }"
}
