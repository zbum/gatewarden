package main

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	failurePatterns = []*regexp.Regexp{
		regexp.MustCompile(`^(?:Failed (?:password|publickey|keyboard-interactive)|Invalid user).* from ([0-9A-Fa-f:.]+) port [0-9]+(?:\s|$)`),
		regexp.MustCompile(`^(?:pam_unix\(sshd:auth\): )?authentication failure;.*\brhost=([0-9A-Fa-f:.]+)(?:\s|$)`),
		regexp.MustCompile(`^Connection closed by authenticating user .* ([0-9A-Fa-f:.]+) port [0-9]+ \[preauth\]$`),
	}
	isoLogPrefix  = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+\S+\s+\S+\[\d+\]:\s+(.*)$`)
	unixLogPrefix = regexp.MustCompile(`^(\d+\.\d+)\s+\S+\s+\S+\[\d+\]:\s+(.*)$`)
	syslogPrefix  = regexp.MustCompile(`^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+\S+\[\d+\]:\s+(.*)$`)
)

func parseFailure(line string) (netip.Addr, bool) {
	_, msg := sshdLine(line)
	for _, pattern := range failurePatterns {
		match := pattern.FindStringSubmatch(msg)
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

// sshdLine removes a journal or syslog prefix. The timestamp is zero when the
// line has none, which is the case for journalctl -o cat.
func sshdLine(line string) (time.Time, string) {
	if match := isoLogPrefix.FindStringSubmatch(line); match != nil {
		when, _ := parseLogTime(match[1])
		return when, match[2]
	}
	if match := unixLogPrefix.FindStringSubmatch(line); match != nil {
		when, ok := parseUnixLogTime(match[1])
		if !ok {
			return time.Time{}, match[2]
		}
		return when, match[2]
	}
	if match := syslogPrefix.FindStringSubmatch(line); match != nil {
		return time.Time{}, match[1]
	}
	return time.Time{}, line
}

func parseLogTime(value string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05Z0700", "2006-01-02T15:04:05.999999999Z0700"} {
		if when, err := time.Parse(layout, value); err == nil {
			return when, true
		}
	}
	return time.Time{}, false
}

func parseUnixLogTime(value string) (time.Time, bool) {
	secText, frac, ok := strings.Cut(value, ".")
	if !ok {
		return time.Time{}, false
	}
	sec, err := strconv.ParseInt(secText, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	frac = (frac + "000000000")[:9]
	nsec, err := strconv.ParseInt(frac, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.Unix(sec, nsec).UTC(), true
}
