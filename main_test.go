package main

import "testing"

func TestConfiguredValueUsesEnvironmentBeforeFallback(t *testing.T) {
	if got := configuredValue("  ens192 ", "eth0"); got != "ens192" {
		t.Fatalf("configuredValue(env) = %q", got)
	}
	if got := configuredValue("  ", "ssh"); got != "ssh" {
		t.Fatalf("configuredValue(empty) = %q", got)
	}
	if got := configuredValue("", ""); got != "" {
		t.Fatalf("configuredValue(blank) = %q", got)
	}
}
