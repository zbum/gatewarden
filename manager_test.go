package main

import (
	"bytes"
	"context"
	"io"
	"log"
	"net/netip"
	"strings"
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

func TestManagerStatusReportsCurrentBlocks(t *testing.T) {
	c := &fakeClock{now: time.Unix(1_000, 0).UTC()}
	fw := &recordingFirewall{}
	m := newManager(time.Minute, 2, 10*time.Minute, nil, fw, c, log.New(io.Discard, "", 0))
	first := netip.MustParseAddr("192.0.2.10")
	second := netip.MustParseAddr("192.0.2.2")
	for _, addr := range []netip.Addr{second, second, first, first} {
		if err := m.RecordFailure(t.Context(), addr); err != nil {
			t.Fatal(err)
		}
	}
	got := m.status()
	if got.FailuresTotal != 4 || got.BlocksTotal != 2 || len(got.Blocks) != 2 {
		t.Fatalf("status = %+v", got)
	}
	if got.Blocks[0].Addr != first || !got.Blocks[0].Until.Equal(c.now.Add(10*time.Minute)) {
		t.Fatalf("first block = %+v", got.Blocks[0])
	}
	c.now = c.now.Add(11 * time.Minute)
	if err := m.Expire(t.Context()); err != nil {
		t.Fatal(err)
	}
	got = m.status()
	if got.UnblocksTotal != 2 || len(got.Blocks) != 0 {
		t.Fatalf("after expiry = %+v", got)
	}
}

func TestConfiguredValuesUseFallbackAndRejectGarbage(t *testing.T) {
	n, err := configuredInt("GATEWARDEN_PERMANENT_AFTER", "", 3)
	if err != nil || n != 3 {
		t.Fatalf("empty int = %d, %v", n, err)
	}
	n, err = configuredInt("GATEWARDEN_PERMANENT_AFTER", "0", 3)
	if err != nil || n != 0 {
		t.Fatalf("zero int = %d, %v", n, err)
	}
	if _, err := configuredInt("GATEWARDEN_PERMANENT_AFTER", "nope", 3); err == nil {
		t.Fatal("expected invalid integer")
	}
	d, err := configuredDuration("GATEWARDEN_PERMANENT_WINDOW", " 24h ", time.Hour)
	if err != nil || d != 24*time.Hour {
		t.Fatalf("duration = %s, %v", d, err)
	}
	if _, err := configuredDuration("GATEWARDEN_PERMANENT_WINDOW", "1d", time.Hour); err == nil {
		t.Fatal("expected invalid duration")
	}
}

func TestOpenSessionKeepsEarlierAccept(t *testing.T) {
	c := &fakeClock{now: time.Unix(5_000, 0).UTC()}
	m := newManager(time.Minute, 1, time.Minute, nil, &recordingFirewall{}, c, log.New(io.Discard, "", 0))
	addr := netip.MustParseAddr("192.0.2.20")
	later := c.now
	earlier := later.Add(-time.Hour)
	if _, created := m.openSession(sessionEvent{user: "keep", addr: addr, port: 41000, pid: 7, when: later}); !created {
		t.Fatal("first accept was treated as a duplicate")
	}
	if _, created := m.openSession(sessionEvent{user: "keep", addr: addr, port: 41000, pid: 8, when: earlier}); created {
		t.Fatal("earlier duplicate replaced the open session")
	}
	if _, created := m.openSession(sessionEvent{user: "keep", addr: addr, port: 41000, pid: 9, when: later.Add(time.Minute)}); created {
		t.Fatal("later duplicate replaced the open session")
	}
	if _, created := m.openSession(sessionEvent{user: "keep", addr: addr, port: 41000, pid: 10}); created {
		t.Fatal("timestamp-less duplicate replaced the open session")
	}
	sessions := m.status().Sessions
	if len(sessions) != 1 || !sessions[0].Since.Equal(earlier) || sessions[0].User != "keep" || sessions[0].PID != 7 {
		t.Fatalf("sessions = %+v", sessions)
	}
	if _, ok := m.closeSession(addr, 1); ok {
		t.Fatal("preauth port closed the open session")
	}
	if _, ok := m.closeSession(addr, 41000); !ok {
		t.Fatal("close missed the open session")
	}
	if len(m.status().Sessions) != 0 {
		t.Fatal("session remained after disconnect")
	}
}

type scriptedWatcher struct {
	events []sessionEvent
}

func (w scriptedWatcher) Run(ctx context.Context, m *manager, logger *log.Logger) error {
	for _, ev := range w.events {
		session, created := m.openSession(ev)
		if created {
			logger.Printf("ssh session open user=%s from=%s port=%d pid=%d", session.User, session.Addr, session.Port, session.PID)
		}
	}
	<-ctx.Done()
	return nil
}

func (scriptedWatcher) Close() error { return nil }

func TestServeCountsLiveFailuresAndWatcherSessions(t *testing.T) {
	fw := &recordingFirewall{}
	var logs bytes.Buffer
	logger := log.New(&logs, "", 0)
	m := newManager(time.Minute, 1, time.Minute, nil, fw, realClock{}, logger)
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	watch := scriptedWatcher{events: []sessionEvent{{
		user: "keep", addr: netip.MustParseAddr("192.0.2.20"), port: 41000, pid: 42, when: since,
	}}}
	liveText := "" +
		"Accepted publickey for git from 2001:db8::5 port 50000 ssh2\n" +
		"Failed password for root from 203.0.113.8 port 22 ssh2\n"
	live := processSource{runner: blockingRunner{output: liveText}, name: "live"}
	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- serve(ctx, live, watch, m, logger) }()

	deadline := time.Now().Add(3 * time.Second)
	var snap statusSnapshot
	for {
		snap = m.status()
		if len(snap.Blocks) == 1 && len(snap.Sessions) == 1 && snap.Sessions[0].User == "keep" && snap.Sessions[0].PID == 42 && snap.Sessions[0].Port == 41000 && snap.Sessions[0].Since.Equal(since) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sessions=%+v blocks=%+v logs=%s", snap.Sessions, snap.Blocks, logs.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	if snap.Blocks[0].Addr.String() != "203.0.113.8" {
		t.Fatalf("blocked %s", snap.Blocks[0].Addr)
	}
	text := logs.String()
	if !strings.Contains(text, "user=keep") || !strings.Contains(text, "pid=42") || strings.Contains(text, "user=git") {
		t.Fatalf("session log = %s", text)
	}
	cancel()
	if err := <-errCh; err != nil {
		t.Fatal(err)
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
