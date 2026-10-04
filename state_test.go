package main

import (
	"errors"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func failUntilBan(t *testing.T, m *manager, addr netip.Addr) {
	t.Helper()
	for range m.threshold {
		if err := m.RecordFailure(t.Context(), addr); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRepeatedBansBecomePermanent(t *testing.T) {
	c := &fakeClock{now: time.Unix(1_000, 0).UTC()}
	fw := &recordingFirewall{}
	m := newManager(time.Minute, 2, 10*time.Minute, nil, fw, c, log.New(io.Discard, "", 0))
	m.configurePermanent(3, 24*time.Hour, "")
	addr := netip.MustParseAddr("192.0.2.50")
	for range 2 {
		failUntilBan(t, m, addr)
		got := m.status()
		if len(got.Blocks) != 1 || got.Blocks[0].Permanent {
			t.Fatalf("temporary block = %+v", got.Blocks)
		}
		c.now = c.now.Add(11 * time.Minute)
		if err := m.Expire(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	before := m.status().FailuresTotal
	failUntilBan(t, m, addr)
	if err := m.RecordFailure(t.Context(), addr); err != nil {
		t.Fatal(err)
	}
	got := m.status()
	if got.FailuresTotal != before+2 || got.BlocksTotal != 3 || got.UnblocksTotal != 2 {
		t.Fatalf("counters = %+v", got)
	}
	if len(got.Blocks) != 1 || !got.Blocks[0].Permanent || !got.Blocks[0].Until.IsZero() {
		t.Fatalf("permanent block = %+v", got.Blocks)
	}
	c.now = c.now.Add(48 * time.Hour)
	if err := m.Expire(t.Context()); err != nil {
		t.Fatal(err)
	}
	got = m.status()
	if len(got.Blocks) != 1 || !got.Blocks[0].Permanent || got.UnblocksTotal != 2 {
		t.Fatalf("after expiry window = %+v", got)
	}
	if len(fw.unblocked) != 2 {
		t.Fatalf("unblocks = %d, want 2", len(fw.unblocked))
	}
}

func TestStrikeOutsideWindowDoesNotPromote(t *testing.T) {
	c := &fakeClock{now: time.Unix(1_000, 0).UTC()}
	m := newManager(time.Minute, 1, 10*time.Minute, nil, &recordingFirewall{}, c, log.New(io.Discard, "", 0))
	m.configurePermanent(2, time.Hour, "")
	addr := netip.MustParseAddr("192.0.2.51")
	failUntilBan(t, m, addr)
	c.now = c.now.Add(11 * time.Minute)
	if err := m.Expire(t.Context()); err != nil {
		t.Fatal(err)
	}
	c.now = c.now.Add(2 * time.Hour)
	failUntilBan(t, m, addr)
	got := m.status()
	if len(got.Blocks) != 1 || got.Blocks[0].Permanent {
		t.Fatalf("block = %+v", got.Blocks)
	}
}

func TestPermanentStateIsRestored(t *testing.T) {
	c := &fakeClock{now: time.Unix(2_000, 0).UTC()}
	path := filepath.Join(t.TempDir(), "state.json")
	m := newManager(time.Minute, 1, time.Minute, nil, &recordingFirewall{}, c, log.New(io.Discard, "", 0))
	m.configurePermanent(2, 24*time.Hour, path)
	addr := netip.MustParseAddr("2001:db8::50")
	other := netip.MustParseAddr("192.0.2.60")
	failUntilBan(t, m, addr)
	c.now = c.now.Add(2 * time.Minute)
	if err := m.Expire(t.Context()); err != nil {
		t.Fatal(err)
	}
	failUntilBan(t, m, addr)
	failUntilBan(t, m, other)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("state mode = %o", info.Mode().Perm())
	}

	later := &fakeClock{now: c.now.Add(48 * time.Hour)}
	fw := &recordingFirewall{}
	restored := newManager(time.Minute, 1, time.Minute, nil, fw, later, log.New(io.Discard, "", 0))
	restored.configurePermanent(2, 24*time.Hour, path)
	if err := restored.load(); err != nil {
		t.Fatal(err)
	}
	if err := restored.applyPermanent(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := restored.status()
	if got.BlocksTotal != 0 || len(got.Blocks) != 1 || got.Blocks[0].Addr != addr || !got.Blocks[0].Permanent {
		t.Fatalf("restored = %+v", got)
	}
	if len(fw.blocked) != 1 || fw.blocked[0] != addr {
		t.Fatalf("applied = %v", fw.blocked)
	}
	if _, ok := restored.strikes[addr]; ok {
		t.Fatal("strike older than the window was kept")
	}
}

func TestPardonResetsStrikes(t *testing.T) {
	c := &fakeClock{now: time.Unix(3_000, 0).UTC()}
	fw := &recordingFirewall{}
	m := newManager(time.Minute, 1, time.Minute, nil, fw, c, log.New(io.Discard, "", 0))
	m.configurePermanent(2, 24*time.Hour, "")
	addr := netip.MustParseAddr("192.0.2.70")
	failUntilBan(t, m, addr)
	c.now = c.now.Add(2 * time.Minute)
	if err := m.Expire(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := m.Pardon(t.Context(), addr); err != nil {
		t.Fatal(err)
	}
	if len(fw.unblocked) != 1 {
		t.Fatalf("pardon of an expired ban unblocked %d times", len(fw.unblocked))
	}
	failUntilBan(t, m, addr)
	if m.status().Blocks[0].Permanent {
		t.Fatal("pardoned strike still counted")
	}
	c.now = c.now.Add(2 * time.Minute)
	if err := m.Expire(t.Context()); err != nil {
		t.Fatal(err)
	}
	failUntilBan(t, m, addr)
	if len(m.status().Blocks) != 1 || !m.status().Blocks[0].Permanent {
		t.Fatalf("second fresh cycle = %+v", m.status().Blocks)
	}
	if err := m.Pardon(t.Context(), addr); err != nil {
		t.Fatal(err)
	}
	if len(m.status().Blocks) != 0 {
		t.Fatalf("after pardon = %+v", m.status().Blocks)
	}
	if err := m.Pardon(t.Context(), addr); !errors.Is(err, errNotBlocked) {
		t.Fatalf("second pardon = %v", err)
	}
}

func TestPardonKeepsRecordWhenUnblockFails(t *testing.T) {
	c := &fakeClock{now: time.Unix(4_000, 0).UTC()}
	fw := &recordingFirewall{}
	m := newManager(time.Minute, 1, time.Minute, nil, fw, c, log.New(io.Discard, "", 0))
	m.configurePermanent(1, time.Hour, "")
	addr := netip.MustParseAddr("192.0.2.71")
	failUntilBan(t, m, addr)
	fw.err = errors.New("boom")
	if err := m.Pardon(t.Context(), addr); err == nil {
		t.Fatal("expected unblock error")
	}
	got := m.status()
	if len(got.Blocks) != 1 || !got.Blocks[0].Permanent {
		t.Fatalf("record after failed pardon = %+v", got.Blocks)
	}
}

func TestShutdownKeepsPermanentRecord(t *testing.T) {
	c := &fakeClock{now: time.Unix(5_000, 0).UTC()}
	path := filepath.Join(t.TempDir(), "state.json")
	fw := &recordingFirewall{}
	m := newManager(time.Minute, 1, time.Minute, nil, fw, c, log.New(io.Discard, "", 0))
	m.configurePermanent(2, 24*time.Hour, path)
	permanent := netip.MustParseAddr("192.0.2.80")
	temporary := netip.MustParseAddr("192.0.2.81")
	failUntilBan(t, m, permanent)
	c.now = c.now.Add(2 * time.Minute)
	if err := m.Expire(t.Context()); err != nil {
		t.Fatal(err)
	}
	failUntilBan(t, m, permanent)
	failUntilBan(t, m, temporary)
	if err := m.UnblockAll(t.Context()); err != nil {
		t.Fatal(err)
	}
	got := m.status()
	if len(got.Blocks) != 1 || got.Blocks[0].Addr != permanent || !got.Blocks[0].Permanent {
		t.Fatalf("after shutdown = %+v", got.Blocks)
	}
	if len(fw.unblocked) != 2 {
		t.Fatalf("shutdown unblocks = %v", fw.unblocked)
	}
	restored := newManager(time.Minute, 1, time.Minute, nil, &recordingFirewall{}, c, log.New(io.Discard, "", 0))
	restored.configurePermanent(2, 24*time.Hour, path)
	if err := restored.load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.permanentSince[permanent]; !ok {
		t.Fatal("permanent ban was erased at shutdown")
	}
}

func TestCorruptStateFailsLoad(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	m := newManager(time.Minute, 1, time.Minute, nil, &recordingFirewall{}, realClock{}, log.New(io.Discard, "", 0))
	m.configurePermanent(3, 24*time.Hour, path)
	if err := m.load(); err == nil {
		t.Fatal("expected corrupt state to fail")
	}
}

func TestOfflinePardonRemovesOneAddress(t *testing.T) {
	c := &fakeClock{now: time.Unix(6_000, 0).UTC()}
	path := filepath.Join(t.TempDir(), "state.json")
	m := newManager(time.Minute, 1, time.Minute, nil, &recordingFirewall{}, c, log.New(io.Discard, "", 0))
	m.configurePermanent(1, time.Hour, path)
	target := netip.MustParseAddr("192.0.2.90")
	keep := netip.MustParseAddr("192.0.2.91")
	failUntilBan(t, m, target)
	failUntilBan(t, m, keep)
	socket := filepath.Join(t.TempDir(), "missing.sock")
	if err := runUnblock([]string{"-socket", socket, "-state-file", path, target.String()}); err != nil {
		t.Fatal(err)
	}
	restored := newManager(time.Minute, 1, time.Minute, nil, &recordingFirewall{}, c, log.New(io.Discard, "", 0))
	restored.configurePermanent(1, time.Hour, path)
	if err := restored.load(); err != nil {
		t.Fatal(err)
	}
	if _, ok := restored.permanentSince[target]; ok {
		t.Fatal("pardoned address remains")
	}
	if _, ok := restored.permanentSince[keep]; !ok {
		t.Fatal("other permanent address was removed")
	}
	if err := runUnblock([]string{"-socket", socket, "-state-file", path, target.String()}); err == nil {
		t.Fatal("expected a missing record to fail")
	}
	if err := runUnblock(nil); err == nil {
		t.Fatal("expected usage error")
	}
}
