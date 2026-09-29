package main

import (
	"context"
	"io"
	"log"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

type runnerCall struct {
	name  string
	args  []string
	stdin string
}
type fakeRunner struct {
	calls []runnerCall
	err   error
}

func (r *fakeRunner) Run(_ context.Context, name string, args []string, stdin io.Reader, _ io.Writer) error {
	var input []byte
	if stdin != nil {
		input, _ = io.ReadAll(stdin)
	}
	r.calls = append(r.calls, runnerCall{name: name, args: slices.Clone(args), stdin: string(input)})
	return r.err
}

func TestNFTFirewallUsesAddressFamilySets(t *testing.T) {
	runner := &fakeRunner{}
	fw, err := newNFTFirewall("nft", "gatewarden", false, runner, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := fw.Block(t.Context(), netip.MustParseAddr("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if err := fw.Block(t.Context(), netip.MustParseAddr("2001:db8::1")); err != nil {
		t.Fatal(err)
	}
	if got := runner.calls[0].args[4]; got != "blocked4" {
		t.Fatalf("IPv4 set = %q", got)
	}
	if got := runner.calls[1].args[4]; got != "blocked6" {
		t.Fatalf("IPv6 set = %q", got)
	}
}

func TestNFTFirewallDryRunDoesNotExecute(t *testing.T) {
	runner := &fakeRunner{}
	fw, err := newNFTFirewall("nft", "gatewarden", true, runner, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := fw.Setup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := fw.Block(t.Context(), netip.MustParseAddr("192.0.2.1")); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("dry-run executed %d commands", len(runner.calls))
	}
}

func TestNFTFirewallRejectsUnsafeTableName(t *testing.T) {
	if _, err := newNFTFirewall("nft", "bad table", false, &fakeRunner{}, log.Default()); err == nil {
		t.Fatal("expected invalid table name error")
	}
}

func TestNFTFirewallSetupDoesNotDeleteExistingTable(t *testing.T) {
	runner := &fakeRunner{}
	fw, err := newNFTFirewall("nft", "gatewarden", false, runner, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := fw.Setup(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("Setup calls = %d, want one atomic batch", len(runner.calls))
	}
	call := runner.calls[0]
	if !slices.Equal(call.args, []string{"-f", "-"}) {
		t.Fatalf("Setup args = %v", call.args)
	}
	if strings.Contains(call.stdin, "delete") {
		t.Fatalf("Setup deleted nftables state: %s", call.stdin)
	}
}
