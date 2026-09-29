package main

import (
	"net/netip"
	"regexp"
)

var failurePatterns = []*regexp.Regexp{
	regexp.MustCompile(`^(?:Failed (?:password|publickey|keyboard-interactive)|Invalid user).* from ([0-9A-Fa-f:.]+) port [0-9]+(?:\s|$)`),
	regexp.MustCompile(`^(?:pam_unix\(sshd:auth\): )?authentication failure;.*\brhost=([0-9A-Fa-f:.]+)(?:\s|$)`),
	regexp.MustCompile(`^Connection closed by authenticating user .* ([0-9A-Fa-f:.]+) port [0-9]+ \[preauth\]$`),
}

func parseFailure(line string) (netip.Addr, bool) {
	for _, pattern := range failurePatterns {
		match := pattern.FindStringSubmatch(line)
		if len(match) != 2 {
			continue
		}
		if addr, err := netip.ParseAddr(match[1]); err == nil {
			addr = addr.Unmap()
			if addr.IsGlobalUnicast() {
				return addr, true
			}
		}
	}
	return netip.Addr{}, false
}
