package main

import "testing"

func TestKernelSSHTracepointsLoad(t *testing.T) {
	requireKernel(t)
	watcher, err := startSSHSessions()
	if err != nil {
		t.Fatal(err)
	}
	if err := watcher.Close(); err != nil {
		t.Fatal(err)
	}
}
