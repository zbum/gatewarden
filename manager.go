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

type statusSnapshot struct {
	Blocks        []blockStatus
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
	return statusSnapshot{Blocks: blocks, FailuresTotal: m.failuresTotal, BlocksTotal: m.blocksTotal, UnblocksTotal: m.unblocksTotal}
}

func serve(ctx context.Context, source lineSource, manager *manager, logger *log.Logger) error {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	followErr := make(chan error, 1)
	go func() {
		followErr <- source.Follow(ctx, func(line string) error {
			addr, ok := parseFailure(line)
			if !ok {
				return nil
			}
			if err := manager.RecordFailure(ctx, addr); err != nil {
				logger.Printf("process failure from %s: %v", addr, err)
			}
			return nil
		})
	}()
	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return manager.UnblockAll(shutdownCtx)
		case err := <-followErr:
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if cleanupErr := manager.UnblockAll(shutdownCtx); cleanupErr != nil {
				return errors.Join(err, cleanupErr)
			}
			return err
		case <-ticker.C:
			if err := manager.Expire(ctx); err != nil {
				logger.Printf("expire blocks: %v", err)
			}
		}
	}
}
