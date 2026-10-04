//go:build !linux

package main

import "errors"

func openEBPF(string) (ebpfSession, error) {
	return nil, errors.New("eBPF enforcement requires Linux")
}
