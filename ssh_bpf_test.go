package main

import (
	"encoding/binary"
	"io"
	"runtime"
	"strings"
	"testing"

	"github.com/cilium/ebpf/asm"
)

func TestSSHTraceProgramsResolve(t *testing.T) {
	programs := []asm.Instructions{
		acceptEnterProgram(1, 24),
		acceptExitProgram(1, 2, 16),
		sessionForkProgram(1, 2, 3, 24, 44),
		sessionExitProgram(1, 2, 24),
	}
	for i, ins := range programs {
		if _, err := ins.SymbolOffsets(); err != nil {
			t.Fatalf("program %d symbols: %v", i, err)
		}
		err := ins.Marshal(io.Discard, binary.LittleEndian)
		if err != nil && !(runtime.GOOS != "linux" && strings.Contains(err.Error(), "not supported")) {
			t.Fatalf("program %d: %v", i, err)
		}
	}
}
