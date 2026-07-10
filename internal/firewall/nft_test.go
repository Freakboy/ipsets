package firewall

import (
	"net/netip"
	"strings"
	"testing"

	"ipsets/internal/store"
)

func TestBuildNFTScriptAllowsWhitelistedIPsAndDropsProtectedPorts(t *testing.T) {
	entries := []store.Entry{
		{IP: "203.0.113.42", Note: "office"},
		{IP: "198.51.100.42/24", Note: "office range"},
		{IP: "2001:db8::8", Note: "ipv6"},
		{IP: "2001:db8:abcd::/48", Note: "ipv6 range"},
	}

	script, err := BuildNFTScript(NFTConfig{
		TableName: "ipguard_test",
		TCPPorts:  []int{22, 443},
	}, entries)
	if err != nil {
		t.Fatalf("BuildNFTScript() error = %v", err)
	}

	for _, want := range []string{
		"table inet ipguard_test",
		"set whitelist_v4",
		"203.0.113.42",
		"198.51.100.0/24",
		"set whitelist_v6",
		"2001:db8::8",
		"2001:db8:abcd::/48",
		"chain prerouting",
		"type filter hook prerouting priority -101; policy accept;",
		"fib daddr type local tcp dport { 22, 443 } ip saddr @whitelist_v4 accept",
		"fib daddr type local tcp dport { 22, 443 } ip6 saddr @whitelist_v6 accept",
		"fib daddr type local tcp dport { 22, 443 } drop",
		"chain input",
		"tcp dport { 22, 443 } ip saddr @whitelist_v4 accept",
		"tcp dport { 22, 443 } ip6 saddr @whitelist_v6 accept",
		"tcp dport { 22, 443 } drop",
	} {
		if !strings.Contains(script, want) {
			t.Fatalf("script missing %q:\n%s", want, script)
		}
	}

	prerouting := strings.Index(script, "chain prerouting")
	if prerouting < 0 {
		t.Fatalf("script missing prerouting chain:\n%s", script)
	}
	preroutingBlock := script[prerouting:]
	loopback := strings.Index(preroutingBlock, "iifname \"lo\" accept")
	firstPortRule := strings.Index(preroutingBlock, "fib daddr type local tcp dport")
	if loopback < 0 || firstPortRule < 0 || loopback > firstPortRule {
		t.Fatalf("prerouting chain must accept loopback before protected port rules:\n%s", script)
	}
}

func TestBuildNFTScriptRejectsBadEntryIP(t *testing.T) {
	_, err := BuildNFTScript(NFTConfig{TableName: "ipsets", TCPPorts: []int{22}}, []store.Entry{{IP: "bad-ip"}})
	if err == nil {
		t.Fatal("BuildNFTScript() error = nil, want invalid IP error")
	}
}

func TestBuildNFTScriptDefaultsToIPSetsTable(t *testing.T) {
	script, err := BuildNFTScript(NFTConfig{TCPPorts: []int{22}}, nil)
	if err != nil {
		t.Fatalf("BuildNFTScript() error = %v", err)
	}
	if !strings.Contains(script, "table inet ipsets") {
		t.Fatalf("script missing default ipsets table:\n%s", script)
	}
	if strings.Contains(script, "elements = {  }") || strings.Contains(script, "elements = { }") {
		t.Fatalf("script contains invalid empty nft set elements:\n%s", script)
	}
}

func TestBuildNFTScriptRemovesEntriesCoveredByCIDR(t *testing.T) {
	script, err := BuildNFTScript(NFTConfig{TableName: "ipsets", TCPPorts: []int{8008}}, []store.Entry{
		{IP: "198.51.100.42"},
		{IP: "198.51.100.0/24"},
	})
	if err != nil {
		t.Fatalf("BuildNFTScript() error = %v", err)
	}
	if strings.Contains(script, "198.51.100.42") {
		t.Fatalf("script contains IP already covered by CIDR:\n%s", script)
	}
	if !strings.Contains(script, "198.51.100.0/24") {
		t.Fatalf("script missing covering CIDR:\n%s", script)
	}
}

func TestNormalizeIPOrCIDRCanonicalizesAddressesAndPrefixes(t *testing.T) {
	ip, err := NormalizeIP(" 203.0.113.42 ")
	if err != nil {
		t.Fatalf("NormalizeIP() error = %v", err)
	}
	if ip != netip.MustParseAddr("203.0.113.42") {
		t.Fatalf("NormalizeIP() = %v", ip)
	}

	address, err := NormalizeIPOrCIDR(" 203.0.113.42/24 ")
	if err != nil {
		t.Fatalf("NormalizeIPOrCIDR() error = %v", err)
	}
	if address.Value != "203.0.113.0/24" || !address.Is4 {
		t.Fatalf("NormalizeIPOrCIDR() = %#v, want canonical IPv4 prefix", address)
	}
}
