package main

import (
	"net/netip"

	"github.com/phuslu/iploc"
)

// lookupCountry resolves a public address to an ISO 3166-1 alpha-2 code.
// Private and unroutable addresses return an empty string. Tests replace this.
var lookupCountry = ipCountryCode

// ipCountryCode uses the embedded IP2Location LITE country database.
func ipCountryCode(addr netip.Addr) string {
	if !addr.IsValid() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() || addr.IsMulticast() || addr.IsUnspecified() {
		return ""
	}
	code := iploc.IPCountry(addr)
	if code == "ZZ" || len(code) != 2 {
		return ""
	}
	for _, r := range code {
		if r < 'A' || r > 'Z' {
			return ""
		}
	}
	return code
}
