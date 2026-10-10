package main

import (
	"net/netip"
	"testing"
)

func TestIPCountryCode(t *testing.T) {
	if got := ipCountryCode(netip.MustParseAddr("8.8.8.8")); got != "US" {
		t.Fatalf("8.8.8.8 = %q", got)
	}
	if got := ipCountryCode(netip.MustParseAddr("192.168.31.102")); got != "" {
		t.Fatalf("private = %q", got)
	}
	if got := ipCountryCode(netip.Addr{}); got != "" {
		t.Fatalf("invalid = %q", got)
	}
}
