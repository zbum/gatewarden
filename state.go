package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"time"
)

var errNotBlocked = errors.New("address is not blocked")

type persistedBan struct {
	IP    string    `json:"ip"`
	Since time.Time `json:"since"`
}

type persistedState struct {
	Permanent []persistedBan         `json:"permanent"`
	Strikes   map[string][]time.Time `json:"strikes"`
}

func (m *manager) rememberBan(addr netip.Addr, now time.Time, failures int) error {
	if m.permanentAfter <= 0 {
		until := now.Add(m.banDuration)
		m.bannedUntil[addr] = until
		m.logger.Printf("blocked %s until %s after %d failures", addr, until.Format(time.RFC3339), failures)
		return m.save()
	}
	cutoff := now.Add(-m.permanentWindow)
	kept := slices.DeleteFunc(slices.Clone(m.strikes[addr]), func(strike time.Time) bool {
		return strike.Before(cutoff)
	})
	kept = append(kept, now)
	m.strikes[addr] = kept
	if len(kept) >= m.permanentAfter {
		m.permanentSince[addr] = now
		delete(m.bannedUntil, addr)
		m.logger.Printf("permanently blocked %s after %d bans within %s", addr, len(kept), m.permanentWindow)
		return m.save()
	}
	until := now.Add(m.banDuration)
	m.bannedUntil[addr] = until
	m.logger.Printf("blocked %s until %s after %d failures", addr, until.Format(time.RFC3339), failures)
	return m.save()
}

func (m *manager) Pardon(ctx context.Context, addr netip.Addr) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, temporary := m.bannedUntil[addr]
	_, permanent := m.permanentSince[addr]
	_, strikes := m.strikes[addr]
	if !temporary && !permanent && !strikes {
		return errNotBlocked
	}
	if temporary || permanent {
		if err := m.firewall.Unblock(ctx, addr); err != nil {
			return fmt.Errorf("unblock %s: %w", addr, err)
		}
	}
	delete(m.bannedUntil, addr)
	delete(m.permanentSince, addr)
	delete(m.strikes, addr)
	m.logger.Printf("pardoned %s", addr)
	return m.save()
}

func (m *manager) applyPermanent(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for addr := range m.permanentSince {
		if err := m.firewall.Block(ctx, addr); err != nil {
			return fmt.Errorf("restore permanent block %s: %w", addr, err)
		}
	}
	return nil
}

func (m *manager) load() error {
	if m.statePath == "" {
		return nil
	}
	data, err := os.ReadFile(m.statePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read ban state: %w", err)
	}
	var stored persistedState
	if err := json.Unmarshal(data, &stored); err != nil {
		return fmt.Errorf("parse ban state: %w", err)
	}
	now := m.clock.Now()
	cutoff := now.Add(-m.permanentWindow)
	strikes := make(map[netip.Addr][]time.Time, len(stored.Strikes))
	for ip, times := range stored.Strikes {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			return fmt.Errorf("ban state address %q: %w", ip, err)
		}
		kept := make([]time.Time, 0, len(times))
		for _, strike := range times {
			if m.permanentWindow <= 0 || !strike.Before(cutoff) {
				kept = append(kept, strike)
			}
		}
		if len(kept) > 0 {
			strikes[addr] = kept
		}
	}
	permanent := make(map[netip.Addr]time.Time, len(stored.Permanent))
	for _, ban := range stored.Permanent {
		addr, err := netip.ParseAddr(ban.IP)
		if err != nil {
			return fmt.Errorf("permanent address %q: %w", ban.IP, err)
		}
		permanent[addr] = ban.Since
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.strikes = strikes
	m.permanentSince = permanent
	return nil
}

func (m *manager) save() error {
	if m.statePath == "" {
		return nil
	}
	stored := persistedState{Permanent: make([]persistedBan, 0, len(m.permanentSince)), Strikes: make(map[string][]time.Time, len(m.strikes))}
	for addr, since := range m.permanentSince {
		stored.Permanent = append(stored.Permanent, persistedBan{IP: addr.String(), Since: since.UTC()})
	}
	for addr, strikes := range m.strikes {
		stored.Strikes[addr.String()] = slices.Clone(strikes)
	}
	slices.SortFunc(stored.Permanent, func(a, b persistedBan) int {
		return cmp.Compare(a.IP, b.IP)
	})
	data, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if err := os.MkdirAll(filepath.Dir(m.statePath), 0o750); err != nil {
		return fmt.Errorf("create ban state directory: %w", err)
	}
	temp := m.statePath + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return fmt.Errorf("write ban state: %w", err)
	}
	if err := os.Rename(temp, m.statePath); err != nil {
		return fmt.Errorf("replace ban state: %w", err)
	}
	return nil
}

func pardonOffline(path string, addr netip.Addr) error {
	m := newManager(time.Minute, 1, time.Minute, nil, nil, realClock{}, log.Default())
	m.configurePermanent(0, 0, path)
	if err := m.load(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	_, permanent := m.permanentSince[addr]
	_, strikes := m.strikes[addr]
	if !permanent && !strikes {
		return errNotBlocked
	}
	delete(m.permanentSince, addr)
	delete(m.strikes, addr)
	m.logger.Printf("pardoned %s in %s", addr, path)
	return m.save()
}

func blocksFromState(path string) ([]blockView, error) {
	m := newManager(time.Minute, 1, time.Minute, nil, nil, realClock{}, log.New(io.Discard, "", 0))
	m.configurePermanent(0, 0, path)
	if err := m.load(); err != nil {
		return nil, err
	}
	return blockViews(m.status()), nil
}
