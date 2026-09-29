package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
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
	mu          sync.Mutex
	window      time.Duration
	threshold   int
	banDuration time.Duration
	allowlist   []netip.Prefix
	firewall    firewall
	clock       clock
	logger      *log.Logger
	failures    map[netip.Addr][]time.Time
	bannedUntil map[netip.Addr]time.Time
}

func newManager(window time.Duration, threshold int, banDuration time.Duration, allowlist []netip.Prefix, fw firewall, c clock, logger *log.Logger) *manager {
	return &manager{window: window, threshold: threshold, banDuration: banDuration, allowlist: allowlist, firewall: fw, clock: c, logger: logger, failures: make(map[netip.Addr][]time.Time), bannedUntil: make(map[netip.Addr]time.Time)}
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
	if len(times) < m.threshold {
		return nil
	}
	if err := m.firewall.Block(ctx, addr); err != nil {
		return fmt.Errorf("block %s: %w", addr, err)
	}
	until := now.Add(m.banDuration)
	m.bannedUntil[addr] = until
	delete(m.failures, addr)
	m.logger.Printf("blocked %s until %s after %d failures", addr, until.Format(time.RFC3339), len(times))
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
