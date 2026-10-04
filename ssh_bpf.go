package main

import "github.com/cilium/ebpf/asm"

// sshCommGate returns 0 unless the current command is sshd, or sshd followed
// by NUL or '-' (sshd-session, sshd-auth). The next instruction is sshd_ok.
// drop is the program's final return.
func sshCommGate() asm.Instructions {
	return asm.Instructions{
		asm.Mov.Imm(asm.R2, 0),
		asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -8, asm.R2, asm.DWord),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -16),
		asm.Mov.Imm(asm.R2, 16),
		asm.FnGetCurrentComm.Call(),
		asm.JSLT.Imm(asm.R0, 0, "drop"),
		asm.LoadMem(asm.R2, asm.RFP, -16, asm.Word),
		asm.JNE.Imm(asm.R2, 0x64687373, "drop"), // "sshd" little-endian
		asm.LoadMem(asm.R2, asm.RFP, -12, asm.Byte),
		asm.JEq.Imm(asm.R2, 0, "sshd_ok"),
		asm.JNE.Imm(asm.R2, int32('-'), "drop"),
	}
}

// acceptEnterProgram saves the user sockaddr pointer from args[1], keyed by
// the accepting pid/tgid. args1 is the byte offset of that pointer in the
// tracepoint context.
func acceptEnterProgram(ptrFD, args1 int) asm.Instructions {
	ins := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	ins = append(ins, sshCommGate()...)
	return append(ins,
		asm.FnGetCurrentPidTgid.Call().WithSymbol("sshd_ok"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMem(asm.R2, asm.R6, int16(args1), asm.DWord),
		asm.StoreMem(asm.RFP, -16, asm.R2, asm.DWord),
		asm.LoadMapPtr(asm.R1, ptrFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("drop"),
		asm.Return(),
	)
}

// acceptExitProgram reads the peer sockaddr filled in by a successful accept
// and stores it under the accepting thread id. The stack below fp is:
// pid/tgid at -8, connection value at -80 (24 bytes), sockaddr at -112
// (32 bytes), and the user pointer at -120.
func acceptExitProgram(ptrFD, pendFD, retOff int) asm.Instructions {
	ins := asm.Instructions{asm.Mov.Reg(asm.R6, asm.R1)}
	ins = append(ins, sshCommGate()...)
	ins = append(ins,
		asm.FnGetCurrentPidTgid.Call().WithSymbol("sshd_ok"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.LoadMem(asm.R0, asm.R6, int16(retOff), asm.DWord),
		asm.JSLT.Imm(asm.R0, 0, "del"),
		asm.LoadMapPtr(asm.R1, ptrFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -120),
		asm.Mov.Imm(asm.R2, 8),
		asm.FnProbeRead.Call(),
		asm.JSLT.Imm(asm.R0, 0, "del"),
		asm.LoadMem(asm.R3, asm.RFP, -120, asm.DWord),
		asm.JEq.Imm(asm.R3, 0, "del"),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -112),
		asm.Mov.Imm(asm.R2, 28),
		asm.FnProbeReadUser.Call(),
		asm.JSLT.Imm(asm.R0, 0, "del"),
		asm.Mov.Imm(asm.R2, 0),
		asm.StoreMem(asm.RFP, -80, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -72, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, -64, asm.R2, asm.DWord),
		asm.LoadMem(asm.R2, asm.RFP, -110, asm.Byte),
		asm.StoreMem(asm.RFP, -78, asm.R2, asm.Byte),
		asm.LoadMem(asm.R2, asm.RFP, -109, asm.Byte),
		asm.StoreMem(asm.RFP, -77, asm.R2, asm.Byte),
		asm.LoadMem(asm.R2, asm.RFP, -112, asm.Byte),
		asm.JEq.Imm(asm.R2, 2, "v4"),
		asm.JEq.Imm(asm.R2, 10, "v6"),
		asm.Ja.Label("del"),
		asm.StoreImm(asm.RFP, -80, 4, asm.Byte).WithSymbol("v4"),
		asm.LoadMem(asm.R2, asm.RFP, -108, asm.Word),
		asm.StoreMem(asm.RFP, -76, asm.R2, asm.Word),
		asm.Ja.Label("publish"),
		asm.StoreImm(asm.RFP, -80, 6, asm.Byte).WithSymbol("v6"),
	)
	ins = append(ins, copyStack(-104, -76, 4)...)
	ins = append(ins,
		asm.LoadMapPtr(asm.R1, pendFD).WithSymbol("publish"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8), // low 4 bytes are the thread id on little-endian
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -80),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.LoadMapPtr(asm.R1, ptrFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapDeleteElem.Call(),
		asm.Ja.Label("drop"),
		asm.LoadMapPtr(asm.R1, ptrFD).WithSymbol("del"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("drop"),
		asm.Return(),
	)
	return ins
}

// sessionForkProgram moves the pending accept from the parent thread to the
// child process, once. A later fork finds nothing to move.
// Stack: connection value at -32, parent tid at -40, child pid at -44,
// event at -96.
func sessionForkProgram(pendFD, connFD, eventsFD, parentOff, childOff int) asm.Instructions {
	ins := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, int16(parentOff), asm.Word),
		asm.StoreMem(asm.RFP, -40, asm.R2, asm.Word),
		asm.LoadMem(asm.R2, asm.R1, int16(childOff), asm.Word),
		asm.StoreMem(asm.RFP, -44, asm.R2, asm.Word),
		asm.LoadMapPtr(asm.R1, pendFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -40),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -32),
		asm.Mov.Imm(asm.R2, connValueLen),
		asm.FnProbeRead.Call(),
		asm.JSLT.Imm(asm.R0, 0, "forget"),
		asm.LoadMapPtr(asm.R1, connFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -44),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -32),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.LoadMapPtr(asm.R1, pendFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -40),
		asm.FnMapDeleteElem.Call(),
	}
	ins = append(ins, emitConnEvent(eventsFD, sshEventOpen, -32, -44, -96)...)
	return append(ins,
		asm.Ja.Label("drop"),
		asm.LoadMapPtr(asm.R1, pendFD).WithSymbol("forget"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -40),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("drop"),
		asm.Return(),
	)
}

// sessionExitProgram emits a close for a process that holds a recorded
// connection. The exiting command is not checked: exec may have replaced it.
// Stack: pid at -4, connection value at -32, event at -64.
func sessionExitProgram(connFD, eventsFD, pidOff int) asm.Instructions {
	ins := asm.Instructions{
		asm.LoadMem(asm.R2, asm.R1, int16(pidOff), asm.Word),
		asm.StoreMem(asm.RFP, -4, asm.R2, asm.Word),
		asm.LoadMapPtr(asm.R1, connFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "drop"),
		asm.Mov.Reg(asm.R3, asm.R0),
		asm.Mov.Reg(asm.R1, asm.RFP),
		asm.Add.Imm(asm.R1, -32),
		asm.Mov.Imm(asm.R2, connValueLen),
		asm.FnProbeRead.Call(),
		asm.JSLT.Imm(asm.R0, 0, "del"),
	}
	ins = append(ins, emitConnEvent(eventsFD, sshEventClose, -32, -4, -64)...)
	return append(ins,
		asm.LoadMapPtr(asm.R1, connFD).WithSymbol("del"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -4),
		asm.FnMapDeleteElem.Call(),
		asm.Mov.Imm(asm.R0, 0).WithSymbol("drop"),
		asm.Return(),
	)
}

// emitConnEvent writes a 24-byte ringbuf sample from a connection value.
// value is the stack offset of the value, pid is the offset of a u32 pid,
// and event is the offset of the 24-byte sample.
func emitConnEvent(eventsFD, kind int, value, pid, event int16) asm.Instructions {
	ins := asm.Instructions{
		asm.Mov.Imm(asm.R2, 0),
		asm.StoreMem(asm.RFP, event, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, event+8, asm.R2, asm.DWord),
		asm.StoreMem(asm.RFP, event+16, asm.R2, asm.DWord),
		asm.StoreImm(asm.RFP, event, int64(kind), asm.Byte),
		asm.LoadMem(asm.R2, asm.RFP, value, asm.Byte),
		asm.StoreMem(asm.RFP, event+1, asm.R2, asm.Byte),
		asm.LoadMem(asm.R2, asm.RFP, value+2, asm.Byte),
		asm.StoreMem(asm.RFP, event+2, asm.R2, asm.Byte),
		asm.LoadMem(asm.R2, asm.RFP, value+3, asm.Byte),
		asm.StoreMem(asm.RFP, event+3, asm.R2, asm.Byte),
		asm.LoadMem(asm.R2, asm.RFP, pid, asm.Word),
		asm.StoreMem(asm.RFP, event+4, asm.R2, asm.Word),
	}
	ins = append(ins, copyStack(value+4, event+8, 4)...)
	return append(ins,
		asm.LoadMapPtr(asm.R1, eventsFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, int32(event)),
		asm.Mov.Imm(asm.R3, sshEventLen),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnRingbufOutput.Call(),
	)
}

func copyStack(src, dst int16, words int) asm.Instructions {
	ins := make(asm.Instructions, 0, words*2)
	for i := range words {
		delta := int16(i * 4)
		ins = append(ins,
			asm.LoadMem(asm.R2, asm.RFP, src+delta, asm.Word),
			asm.StoreMem(asm.RFP, dst+delta, asm.R2, asm.Word),
		)
	}
	return ins
}
