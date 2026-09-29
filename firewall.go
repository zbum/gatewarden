package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os/exec"
	"regexp"
	"strings"
)

type execRunner struct{}

func (execRunner) Run(ctx context.Context, name string, args []string, stdin io.Reader, stdout io.Writer) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = stdin
	cmd.Stdout = stdout
	cmd.Stderr = stdout
	return cmd.Run()
}

type nftFirewall struct {
	binary, table string
	dryRun        bool
	runner        commandRunner
	logger        *log.Logger
}

var nftIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)

func newNFTFirewall(binary, table string, dryRun bool, runner commandRunner, logger *log.Logger) (*nftFirewall, error) {
	if strings.TrimSpace(binary) == "" {
		return nil, fmt.Errorf("nft binary must not be empty")
	}
	if !nftIdentifier.MatchString(table) {
		return nil, fmt.Errorf("invalid nft table name %q", table)
	}
	return &nftFirewall{binary: binary, table: table, dryRun: dryRun, runner: runner, logger: logger}, nil
}

func (f *nftFirewall) Setup(ctx context.Context) error {
	script := fmt.Sprintf(`add table inet %s
add set inet %s blocked4 { type ipv4_addr; }
add set inet %s blocked6 { type ipv6_addr; }
add chain inet %s input { type filter hook input priority -10; policy accept; }
add rule inet %s input ip saddr @blocked4 drop
add rule inet %s input ip6 saddr @blocked6 drop
`, f.table, f.table, f.table, f.table, f.table, f.table)
	f.logger.Printf("nft: %s -f - (create table %s)", f.binary, f.table)
	if f.dryRun {
		return nil
	}
	if err := f.runner.Run(ctx, f.binary, []string{"-f", "-"}, strings.NewReader(script), io.Discard); err != nil {
		return fmt.Errorf("create nft table %s: %w", f.table, err)
	}
	return nil
}

func (f *nftFirewall) Teardown(ctx context.Context) error {
	return f.run(ctx, []string{"delete", "table", "inet", f.table})
}
func (f *nftFirewall) Block(ctx context.Context, addr netip.Addr) error {
	return f.element(ctx, "add", addr)
}
func (f *nftFirewall) Unblock(ctx context.Context, addr netip.Addr) error {
	return f.element(ctx, "delete", addr)
}
func (f *nftFirewall) element(ctx context.Context, operation string, addr netip.Addr) error {
	set := "blocked6"
	if addr.Is4() {
		set = "blocked4"
	}
	return f.run(ctx, []string{operation, "element", "inet", f.table, set, "{", addr.String(), "}"})
}
func (f *nftFirewall) run(ctx context.Context, args []string) error {
	f.logger.Printf("nft: %s %s", f.binary, strings.Join(args, " "))
	if f.dryRun {
		return nil
	}
	if err := f.runner.Run(ctx, f.binary, args, nil, io.Discard); err != nil {
		return fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
	}
	return nil
}
