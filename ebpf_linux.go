package main

import (
	"errors"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
)

type kernelSession struct {
	blocked    *ebpf.Map
	program    *ebpf.Program
	attachment link.Link
}

func openEBPF(name string) (ebpfSession, error) {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return nil, fmt.Errorf("find interface: %w", err)
	}
	if len(iface.HardwareAddr) != 6 || iface.Flags&net.FlagLoopback != 0 {
		return nil, errors.New("XDP requires an Ethernet interface")
	}
	s, err := loadKernelSession()
	if err != nil {
		return nil, err
	}
	s.attachment, err = link.AttachXDP(link.XDPOptions{Program: s.program, Interface: iface.Index, Flags: link.XDPGenericMode})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("attach XDP to %s: %w", name, err), s.Close())
	}
	return s, nil
}
func loadKernelSession() (*kernelSession, error) {
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "gw_blocked", Type: ebpf.Hash, KeySize: 20, ValueSize: 1, MaxEntries: 65536})
	if err != nil {
		return nil, fmt.Errorf("create block map: %w", err)
	}
	s := &kernelSession{blocked: m}
	s.program, err = ebpf.NewProgram(&ebpf.ProgramSpec{Name: "gw_ingress", Type: ebpf.XDP, License: "GPL", Instructions: blockInstructions(m.FD())})
	if err != nil {
		return nil, errors.Join(fmt.Errorf("load XDP: %w", err), s.Close())
	}
	return s, nil
}
func (s *kernelSession) Set(key [20]byte, blocked bool) error {
	if blocked {
		return s.blocked.Update(key, uint8(1), ebpf.UpdateAny)
	}
	err := s.blocked.Delete(key)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}
func (s *kernelSession) Close() error {
	var errs []error
	if s.attachment != nil {
		errs = append(errs, s.attachment.Close())
		s.attachment = nil
	}
	if s.program != nil {
		errs = append(errs, s.program.Close())
		s.program = nil
	}
	if s.blocked != nil {
		errs = append(errs, s.blocked.Close())
		s.blocked = nil
	}
	return errors.Join(errs...)
}

// Stack key: one family byte, three zero bytes, then 16 network-order IP bytes.
func blockInstructions(fd int) asm.Instructions {
	ins := asm.Instructions{
		asm.LoadMem(asm.R6, asm.R1, 0, asm.Word),
		asm.LoadMem(asm.R7, asm.R1, 4, asm.Word),
		asm.Mov.Reg(asm.R2, asm.R6), asm.Add.Imm(asm.R2, 14),
		asm.JGT.Reg(asm.R2, asm.R7, "pass"),
		asm.LoadMem(asm.R8, asm.R6, 12, asm.Half), asm.HostTo(asm.BE, asm.R8, asm.Half),
		asm.Add.Imm(asm.R6, 14),
	}
	for i := range 2 {
		vlan, next := fmt.Sprintf("vlan%d", i), fmt.Sprintf("next%d", i)
		ins = append(ins,
			asm.JEq.Imm(asm.R8, 0x8100, vlan), asm.JNE.Imm(asm.R8, 0x88a8, next),
			asm.Mov.Reg(asm.R2, asm.R6).WithSymbol(vlan), asm.Add.Imm(asm.R2, 4),
			asm.JGT.Reg(asm.R2, asm.R7, "pass"),
			asm.LoadMem(asm.R8, asm.R6, 2, asm.Half), asm.HostTo(asm.BE, asm.R8, asm.Half),
			asm.Add.Imm(asm.R6, 4), asm.Mov.Reg(asm.R2, asm.R6).WithSymbol(next),
		)
	}
	ins = append(ins,
		asm.Mov.Imm(asm.R3, 0),
		asm.StoreMem(asm.RFP, -24, asm.R3, asm.DWord),
		asm.StoreMem(asm.RFP, -16, asm.R3, asm.DWord),
		asm.StoreMem(asm.RFP, -8, asm.R3, asm.DWord),
		asm.JEq.Imm(asm.R8, 0x0800, "ipv4"), asm.JEq.Imm(asm.R8, 0x86dd, "ipv6"), asm.Ja.Label("pass"),
		asm.Mov.Reg(asm.R2, asm.R6).WithSymbol("ipv4"), asm.Add.Imm(asm.R2, 20), asm.JGT.Reg(asm.R2, asm.R7, "pass"),
		asm.StoreImm(asm.RFP, -24, 4, asm.Byte),
		asm.LoadMem(asm.R3, asm.R6, 12, asm.Word), asm.StoreMem(asm.RFP, -20, asm.R3, asm.Word), asm.Ja.Label("lookup"),
		asm.Mov.Reg(asm.R2, asm.R6).WithSymbol("ipv6"), asm.Add.Imm(asm.R2, 40), asm.JGT.Reg(asm.R2, asm.R7, "pass"),
		asm.StoreImm(asm.RFP, -24, 6, asm.Byte),
	)
	for i := range 4 {
		ins = append(ins, asm.LoadMem(asm.R3, asm.R6, int16(8+i*4), asm.Word), asm.StoreMem(asm.RFP, int16(-20+i*4), asm.R3, asm.Word))
	}
	return append(ins,
		asm.LoadMapPtr(asm.R1, fd).WithSymbol("lookup"), asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -24),
		asm.FnMapLookupElem.Call(), asm.JEq.Imm(asm.R0, 0, "pass"),
		asm.Mov.Imm(asm.R0, 1), asm.Return(),
		asm.Mov.Imm(asm.R0, 2).WithSymbol("pass"), asm.Return(),
	)
}
