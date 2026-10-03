package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"strings"
)

type ebpfSession interface {
	Set([20]byte, bool) error
	Close() error
}

type ebpfFirewall struct {
	iface   string
	dryRun  bool
	logger  *log.Logger
	open    func(string) (ebpfSession, error)
	session ebpfSession
}

func newEBPFFirewall(iface string, dryRun bool, logger *log.Logger) (*ebpfFirewall, error) {
	if strings.TrimSpace(iface) == "" {
		return nil, errors.New("eBPF requires -interface or GATEWARDEN_INTERFACE (Ethernet ingress interface)")
	}
	return &ebpfFirewall{iface: iface, dryRun: dryRun, logger: logger, open: openEBPF}, nil
}

func (f *ebpfFirewall) Setup(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if f.session != nil {
		return errors.New("eBPF firewall already started")
	}
	f.logger.Printf("ebpf: attach generic XDP to %s", f.iface)
	if f.dryRun {
		return nil
	}
	session, err := f.open(f.iface)
	if err != nil {
		return err
	}
	f.session = session
	return nil
}
func (f *ebpfFirewall) Teardown(context.Context) error {
	if f.session == nil {
		return nil
	}
	err := f.session.Close()
	f.session = nil
	return err
}
func (f *ebpfFirewall) Block(ctx context.Context, addr netip.Addr) error {
	return f.set(ctx, addr, true)
}
func (f *ebpfFirewall) Unblock(ctx context.Context, addr netip.Addr) error {
	return f.set(ctx, addr, false)
}
func (f *ebpfFirewall) set(ctx context.Context, addr netip.Addr, blocked bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key, err := addressKey(addr)
	if err != nil {
		return err
	}
	f.logger.Printf("ebpf: interface=%s address=%s blocked=%t", f.iface, addr, blocked)
	if f.dryRun {
		return nil
	}
	if f.session == nil {
		return errors.New("eBPF firewall is not started")
	}
	if err := f.session.Set(key, blocked); err != nil {
		return fmt.Errorf("update eBPF block for %s: %w", addr, err)
	}
	return nil
}
func addressKey(addr netip.Addr) ([20]byte, error) {
	var key [20]byte
	if !addr.IsValid() || addr.Zone() != "" {
		return key, errors.New("invalid or scoped block address")
	}
	addr = addr.Unmap()
	if addr.Is4() {
		key[0] = 4
		value := addr.As4()
		copy(key[4:], value[:])
	} else {
		key[0] = 6
		value := addr.As16()
		copy(key[4:], value[:])
	}
	return key, nil
}
