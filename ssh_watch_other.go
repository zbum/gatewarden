//go:build !linux

package main

import "errors"

func startSSHSessions() (sessionWatcher, error) {
	return nil, errors.New("eBPF session watch requires Linux")
}
