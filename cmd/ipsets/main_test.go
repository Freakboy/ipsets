package main

import "testing"

func TestNewPasswordUsesEnvironmentForAutomation(t *testing.T) {
	t.Setenv("IPSETS_NEW_PASSWORD", "automated-secret")
	password, err := newPassword()
	if err != nil {
		t.Fatalf("newPassword() error = %v", err)
	}
	if password != "automated-secret" {
		t.Fatalf("newPassword() = %q, want environment value", password)
	}
}
