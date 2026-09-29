package main

import "testing"

func TestParseFailure(t *testing.T) {
	tests := []struct {
		name, line, want string
		ok               bool
	}{
		{"password", "Failed password for invalid user root from 192.0.2.10 port 22 ssh2", "192.0.2.10", true},
		{"invalid user", "Invalid user admin from 2001:db8::2 port 50000", "2001:db8::2", true},
		{"pam", "pam_unix(sshd:auth): authentication failure; logname= uid=0 rhost=198.51.100.4 user=root", "198.51.100.4", true},
		{"username cannot spoof source", "Failed password for invalid user x from 203.0.113.9 from 192.0.2.10 port 22 ssh2", "192.0.2.10", true},
		{"unspecified address", "Failed password for root from 0.0.0.0 port 22 ssh2", "", false},
		{"unrelated", "Accepted publickey for user from 192.0.2.10 port 22", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseFailure(tt.line)
			if ok != tt.ok || (ok && got.String() != tt.want) {
				t.Fatalf("parseFailure() = %s, %v; want %s, %v", got, ok, tt.want, tt.ok)
			}
		})
	}
}
