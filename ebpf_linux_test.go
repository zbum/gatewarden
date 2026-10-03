package main

import (
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"slices"
	"testing"
)

func requireKernel(t *testing.T) {
	t.Helper()
	if os.Getenv("GATEWARDEN_TEST_EBPF") != "1" {
		t.Skip("set GATEWARDEN_TEST_EBPF=1 on privileged Linux to test the kernel")
	}
}
func TestKernelPacketDecisions(t *testing.T) {
	requireKernel(t)
	s, err := loadKernelSession()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		addr := netip.MustParseAddr(ip)
		key, _ := addressKey(addr)
		for tags := range 3 {
			packet := make([]byte, 14+4*tags+40)
			offset := 12
			for i := range tags {
				tag := uint16(0x8100)
				if i == 0 {
					tag = 0x88a8
				}
				binary.BigEndian.PutUint16(packet[offset:], tag)
				offset += 4
			}
			if addr.Is4() {
				binary.BigEndian.PutUint16(packet[offset:], 0x0800)
				packet[offset+2] = 0x45
				src := addr.As4()
				copy(packet[offset+14:], src[:])
			} else {
				binary.BigEndian.PutUint16(packet[offset:], 0x86dd)
				packet[offset+2] = 0x60
				src := addr.As16()
				copy(packet[offset+10:], src[:])
			}
			check := func(want uint32) {
				t.Helper()
				got, _, err := s.program.Test(packet)
				if err != nil || got != want {
					t.Fatalf("ip=%s tags=%d action=%d want=%d err=%v", ip, tags, got, want, err)
				}
			}
			check(2)
			if err := s.Set(key, true); err != nil {
				t.Fatal(err)
			}
			check(1)
			other := slices.Clone(packet)
			// Change the source, leaving the address family and Ethernet headers intact.
			srcOffset := offset + 14
			if !addr.Is4() {
				srcOffset = offset + 10
			}
			other[srcOffset] ^= 1
			got, _, err := s.program.Test(other)
			if err != nil || got != 2 {
				t.Fatalf("unblocked source action=%d: %v", got, err)
			}
			if err := s.Set(key, false); err != nil {
				t.Fatal(err)
			}
			check(2)
			if err := s.Set(key, false); err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, packet := range [][]byte{make([]byte, 14), append(make([]byte, 12), 0x08, 0x00), append(make([]byte, 12), 0x86, 0xdd), append(make([]byte, 12), 0x81, 0x00)} {
		got, _, err := s.program.Test(packet)
		if err != nil || got != 2 {
			t.Fatalf("short/non-IP action=%d: %v", got, err)
		}
	}
}
func TestKernelAttachmentOwnership(t *testing.T) {
	requireKernel(t)
	name := os.Getenv("GATEWARDEN_TEST_INTERFACE")
	if name == "" {
		t.Skip("set disposable test interface")
	}
	first, err := openEBPF(name)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if second, err := openEBPF(name); err == nil {
		second.Close()
		t.Fatal("replaced existing XDP program")
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	second, err := openEBPF(name)
	if err != nil {
		t.Fatalf("reattach after teardown: %v", err)
	}
	defer second.Close()
	iface, _ := net.InterfaceByName(name)
	if iface == nil {
		t.Fatal("missing test interface")
	}
	// Confirm the attachment is a BPF link, rather than a persistent netlink attach.
	if _, err := second.(*kernelSession).attachment.Info(); err != nil {
		t.Fatal(err)
	}
}
