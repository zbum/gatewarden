package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/netip"
	"testing"
)

type fakeEBPFSession struct {
	entries map[[20]byte]bool
	closed  bool
	err     error
}

func (s *fakeEBPFSession) Set(k [20]byte, block bool) error {
	if s.err != nil {
		return s.err
	}
	if block {
		s.entries[k] = true
	} else {
		delete(s.entries, k)
	}
	return nil
}
func (s *fakeEBPFSession) Close() error { s.closed = true; return s.err }
func TestEBPFLifecycle(t *testing.T) {
	f, err := newEBPFFirewall("eth0", false, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeEBPFSession{entries: make(map[[20]byte]bool)}
	f.open = func(string) (ebpfSession, error) { return s, nil }
	addr := netip.MustParseAddr("192.0.2.1")
	if f.Block(t.Context(), addr) == nil {
		t.Fatal("block before setup succeeded")
	}
	if err := f.Setup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.Setup(t.Context()) == nil {
		t.Fatal("duplicate setup succeeded")
	}
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		addr := netip.MustParseAddr(ip)
		if err := f.Block(t.Context(), addr); err != nil {
			t.Fatal(err)
		}
		key, _ := addressKey(addr)
		if !s.entries[key] {
			t.Fatal("missing ban")
		}
		if err := f.Unblock(t.Context(), addr); err != nil {
			t.Fatal(err)
		}
		if s.entries[key] {
			t.Fatal("ban not removed")
		}
	}
	want := errors.New("map full")
	s.err = want
	if !errors.Is(f.Block(t.Context(), addr), want) {
		t.Fatal("lost map error")
	}
	s.err = nil
	if err := f.Teardown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !s.closed {
		t.Fatal("session not closed")
	}
	if err := f.Teardown(t.Context()); err != nil {
		t.Fatal(err)
	}
}
func TestEBPFDryRunAndErrors(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	if _, err := newEBPFFirewall("", true, logger); err == nil {
		t.Fatal("missing interface accepted")
	}
	f, _ := newEBPFFirewall("eth0", true, logger)
	f.open = func(string) (ebpfSession, error) { t.Fatal("dry run opened kernel"); return nil, nil }
	if err := f.Setup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := f.Block(t.Context(), netip.MustParseAddr("::ffff:192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if err := f.Unblock(t.Context(), netip.MustParseAddr("2001:db8::1")); err != nil {
		t.Fatal(err)
	}
	if err := f.Teardown(t.Context()); err != nil {
		t.Fatal(err)
	}
	for _, addr := range []netip.Addr{{}, netip.MustParseAddr("fe80::1%eth0")} {
		if f.Block(t.Context(), addr) == nil {
			t.Fatal("invalid address accepted")
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if !errors.Is(f.Setup(ctx), context.Canceled) || !errors.Is(f.Block(ctx, netip.MustParseAddr("192.0.2.1")), context.Canceled) {
		t.Fatal("cancellation ignored")
	}
	f.dryRun = false
	want := errors.New("attach failed")
	f.open = func(string) (ebpfSession, error) { return nil, want }
	if !errors.Is(f.Setup(t.Context()), want) {
		t.Fatal("lost setup error")
	}
	if f.session != nil {
		t.Fatal("failed setup retained session")
	}
}
func TestAddressKeys(t *testing.T) {
	k4, _ := addressKey(netip.MustParseAddr("192.0.2.1"))
	mapped, _ := addressKey(netip.MustParseAddr("::ffff:192.0.2.1"))
	if k4 != mapped || k4 != [20]byte{4, 0, 0, 0, 192, 0, 2, 1} {
		t.Fatalf("IPv4 key: %v", k4)
	}
	k6, _ := addressKey(netip.MustParseAddr("2001:db8::1"))
	if k6[0] != 6 || k6[4] != 0x20 || k6[19] != 1 {
		t.Fatalf("IPv6 key: %v", k6)
	}
}
