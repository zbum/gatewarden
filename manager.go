package main

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"sync"
	"time"
)

type firewall interface {
	Block(context.Context, netip.Addr) error
	Unblock(context.Context, netip.Addr) error
}
type clock interface{ Now() time.Time }
type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

type manager struct {
	mu              sync.Mutex
	window          time.Duration
	threshold       int
	banDuration     time.Duration
	allowlist       []netip.Prefix
	firewall        firewall
	clock           clock
	logger          *log.Logger
	failures        map[netip.Addr][]time.Time
	bannedUntil     map[netip.Addr]time.Time
	strikes         map[netip.Addr][]time.Time
	permanentSince  map[netip.Addr]time.Time
	sessions        map[sessionKey]sshSession
	permanentAfter  int
	permanentWindow time.Duration
	statePath       string
	failuresTotal   uint64
	blocksTotal     uint64
	unblocksTotal   uint64
}

func newManager(window time.Duration, threshold int, banDuration time.Duration, allowlist []netip.Prefix, fw firewall, c clock, logger *log.Logger) *manager {
	return &manager{
		window: window, threshold: threshold, banDuration: banDuration, allowlist: allowlist, firewall: fw, clock: c, logger: logger,
		failures: make(map[netip.Addr][]time.Time), bannedUntil: make(map[netip.Addr]time.Time),
		strikes: make(map[netip.Addr][]time.Time), permanentSince: make(map[netip.Addr]time.Time),
		sessions: make(map[sessionKey]sshSession),
	}
}

func (m *manager) configurePermanent(after int, window time.Duration, statePath string) {
	m.permanentAfter = after
	m.permanentWindow = window
	m.statePath = statePath
}

func (m *manager) RecordFailure(ctx context.Context, addr netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, prefix := range m.allowlist {
		if prefix.Contains(addr) {
			return nil
		}
	}
	now := m.clock.Now()
	if _, ok := m.permanentSince[addr]; ok {
		return nil
	}
	if until, ok := m.bannedUntil[addr]; ok && now.Before(until) {
		return nil
	}
	cutoff := now.Add(-m.window)
	times := m.failures[addr]
	firstCurrent := 0
	for firstCurrent < len(times) && times[firstCurrent].Before(cutoff) {
		firstCurrent++
	}
	times = append(times[firstCurrent:], now)
	m.failures[addr] = times
	m.failuresTotal++
	if len(times) < m.threshold {
		return nil
	}
	if err := m.firewall.Block(ctx, addr); err != nil {
		return fmt.Errorf("block %s: %w", addr, err)
	}
	failures := len(times)
	delete(m.failures, addr)
	m.blocksTotal++
	if err := m.rememberBan(addr, now, failures); err != nil {
		return err
	}
	return nil
}

func (m *manager) Expire(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.clock.Now()
	for addr, until := range m.bannedUntil {
		if now.Before(until) {
			continue
		}
		if err := m.firewall.Unblock(ctx, addr); err != nil {
			return fmt.Errorf("unblock %s: %w", addr, err)
		}
		delete(m.bannedUntil, addr)
		m.unblocksTotal++
		m.logger.Printf("unblocked %s after ban expired", addr)
	}
	return nil
}

func (m *manager) UnblockAll(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for addr := range m.bannedUntil {
		if err := m.firewall.Unblock(ctx, addr); err != nil {
			return fmt.Errorf("unblock %s during shutdown: %w", addr, err)
		}
		delete(m.bannedUntil, addr)
	}
	return nil
}

type blockStatus struct {
	Addr      netip.Addr
	Until     time.Time
	Permanent bool
}

type sessionKey struct {
	addr netip.Addr
	port uint16
}

type sshSession struct {
	User  string
	Addr  netip.Addr
	Port  uint16
	PID   int
	Since time.Time
}

type statusSnapshot struct {
	Blocks        []blockStatus
	Sessions      []sshSession
	FailuresTotal uint64
	BlocksTotal   uint64
	UnblocksTotal uint64
}

func (m *manager) status() statusSnapshot {
	m.mu.Lock()
	defer m.mu.Unlock()
	blocks := make([]blockStatus, 0, len(m.bannedUntil)+len(m.permanentSince))
	for addr, until := range m.bannedUntil {
		blocks = append(blocks, blockStatus{Addr: addr, Until: until})
	}
	for addr := range m.permanentSince {
		blocks = append(blocks, blockStatus{Addr: addr, Permanent: true})
	}
	slices.SortFunc(blocks, func(a, b blockStatus) int {
		return cmp.Compare(a.Addr.String(), b.Addr.String())
	})
	sessions := make([]sshSession, 0, len(m.sessions))
	for _, session := range m.sessions {
		sessions = append(sessions, session)
	}
	slices.SortFunc(sessions, func(a, b sshSession) int {
		if c := a.Since.Compare(b.Since); c != 0 {
			return c
		}
		if c := cmp.Compare(a.Addr.String(), b.Addr.String()); c != 0 {
			return c
		}
		return cmp.Compare(a.Port, b.Port)
	})
	return statusSnapshot{Blocks: blocks, Sessions: sessions, FailuresTotal: m.failuresTotal, BlocksTotal: m.blocksTotal, UnblocksTotal: m.unblocksTotal}
}

// openSession records an SSH connection. A repeated event for the same
// source keeps the earlier timestamp and the first process id.
func (m *manager) openSession(ev sessionEvent) (sshSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := sessionKey{addr: ev.addr, port: ev.port}
	if prev, ok := m.sessions[key]; ok {
		if !ev.when.IsZero() && ev.when.Before(prev.Since) {
			prev.Since = ev.when
			m.sessions[key] = prev
		}
		return m.sessions[key], false
	}
	when := ev.when
	if when.IsZero() {
		when = m.clock.Now()
	}
	session := sshSession{User: ev.user, Addr: ev.addr, Port: ev.port, PID: ev.pid, Since: when}
	m.sessions[key] = session
	return session, true
}

func (m *manager) closeSession(addr netip.Addr, port uint16) (sshSession, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	session, ok := m.sessions[sessionKey{addr: addr, port: port}]
	if ok {
		delete(m.sessions, sessionKey{addr: addr, port: port})
	}
	return session, ok
}

func applyLogLine(ctx context.Context, m *manager, logger *log.Logger, line string) {
	addr, ok := parseFailure(line)
	if !ok {
		return
	}
	if err := m.RecordFailure(ctx, addr); err != nil {
		logger.Printf("process failure from %s: %v", addr, err)
	}
}

func serve(ctx context.Context, source lineSource, sessions sessionWatcher, manager *manager, logger *log.Logger) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	errCh := make(chan error, 2)
	go func() {
		errCh <- source.Follow(ctx, func(line string) error {
			applyLogLine(ctx, manager, logger, line)
			return nil
		})
	}()
	go func() {
		errCh <- sessions.Run(ctx, manager, logger)
	}()
	for {
		select {
		case <-ctx.Done():
			return stopFirewall(manager, nil, false)
		case err := <-errCh:
			return stopFirewall(manager, err, ctx.Err() == nil)
		case <-ticker.C:
			if err := manager.Expire(ctx); err != nil {
				logger.Printf("expire blocks: %v", err)
			}
		}
	}
}

func stopFirewall(manager *manager, err error, keepErr bool) error {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cleanupErr := manager.UnblockAll(shutdownCtx)
	if keepErr && err != nil {
		return errors.Join(err, cleanupErr)
	}
	if cleanupErr != nil {
		return cleanupErr
	}
	if keepErr {
		return err
	}
	return nil
}
