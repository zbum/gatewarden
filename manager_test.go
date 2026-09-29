package main

import (
	"context"
	"io"
	"log"
	"net/netip"
	"testing"
	"time"
)

type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time { return c.now }

type recordingFirewall struct {
	blocked, unblocked []netip.Addr
	err                error
}

func (f *recordingFirewall) Block(_ context.Context, addr netip.Addr) error {
	if f.err != nil {
		return f.err
	}
	f.blocked = append(f.blocked, addr)
	return nil
}
func (f *recordingFirewall) Unblock(_ context.Context, addr netip.Addr) error {
	if f.err != nil {
		return f.err
	}
	f.unblocked = append(f.unblocked, addr)
	return nil
}

func TestManagerBlocksOnceAtThresholdAndExpires(t *testing.T) {
	c := &fakeClock{now: time.Unix(1000, 0)}
	fw := &recordingFirewall{}
	m := newManager(time.Minute, 3, 10*time.Minute, nil, fw, c, log.New(io.Discard, "", 0))
	addr := netip.MustParseAddr("192.0.2.3")
	for range 4 {
		if err := m.RecordFailure(t.Context(), addr); err != nil {
			t.Fatal(err)
		}
	}
	if len(fw.blocked) != 1 {
		t.Fatalf("blocks = %d, want 1", len(fw.blocked))
	}
	c.now = c.now.Add(11 * time.Minute)
	if err := m.Expire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(fw.unblocked) != 1 {
		t.Fatalf("unblocks = %d, want 1", len(fw.unblocked))
	}
}

func TestManagerRollingWindowAndAllowlist(t *testing.T) {
	c := &fakeClock{now: time.Unix(1000, 0)}
	fw := &recordingFirewall{}
	m := newManager(time.Minute, 2, time.Minute, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, fw, c, log.New(io.Discard, "", 0))
	if err := m.RecordFailure(t.Context(), netip.MustParseAddr("10.0.0.1")); err != nil {
		t.Fatal(err)
	}
	addr := netip.MustParseAddr("192.0.2.1")
	if err := m.RecordFailure(t.Context(), addr); err != nil {
		t.Fatal(err)
	}
	c.now = c.now.Add(2 * time.Minute)
	if err := m.RecordFailure(t.Context(), addr); err != nil {
		t.Fatal(err)
	}
	if len(fw.blocked) != 0 {
		t.Fatalf("blocks = %d, want 0", len(fw.blocked))
	}
}

func TestParseAllowlistRejectsInvalidEntry(t *testing.T) {
	if _, err := parseAllowlist("not-an-ip"); err == nil {
		t.Fatal("expected invalid allowlist error")
	}
	prefixes, err := parseAllowlist("192.0.2.1, 2001:db8::/32")
	if err != nil || len(prefixes) != 2 {
		t.Fatalf("parseAllowlist() = %v, %v", prefixes, err)
	}
}
