package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type options struct {
	logFile     string
	journalUnit string
	window      time.Duration
	threshold   int
	banDuration time.Duration
	allowlist   string
	nftBinary   string
	nftTable    string
	dryRun      bool
}

func main() {
	if err := run(); err != nil {
		log.Printf("gatewarden: %v", err)
		os.Exit(1)
	}
}

func run() error {
	var opts options
	flag.StringVar(&opts.logFile, "log-file", "", "follow this SSH log file instead of journald")
	flag.StringVar(&opts.journalUnit, "journal-unit", "ssh", "systemd unit to follow (commonly ssh or sshd)")
	flag.DurationVar(&opts.window, "window", 5*time.Minute, "rolling failure window")
	flag.IntVar(&opts.threshold, "threshold", 5, "failures in the window before blocking")
	flag.DurationVar(&opts.banDuration, "ban-duration", 15*time.Minute, "duration of a block")
	flag.StringVar(&opts.allowlist, "allowlist", "127.0.0.0/8,::1/128", "comma-separated IP addresses or CIDRs never blocked")
	flag.StringVar(&opts.nftBinary, "nft-binary", "nft", "nft executable path")
	flag.StringVar(&opts.nftTable, "nft-table", "gatewarden", "nftables inet table name")
	flag.BoolVar(&opts.dryRun, "dry-run", false, "log firewall changes without executing nft")
	flag.Parse()
	if opts.window <= 0 || opts.threshold <= 0 || opts.banDuration <= 0 {
		return errors.New("window, threshold, and ban-duration must be positive")
	}
	allowlist, err := parseAllowlist(opts.allowlist)
	if err != nil {
		return err
	}
	runner := execRunner{}
	fw, err := newNFTFirewall(opts.nftBinary, opts.nftTable, opts.dryRun, runner, log.Default())
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := fw.Setup(ctx); err != nil {
		return fmt.Errorf("set up firewall: %w", err)
	}
	defer func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := fw.Teardown(cleanupCtx); err != nil {
			log.Printf("gatewarden: tear down firewall: %v", err)
		}
	}()
	source := processSource{runner: runner}
	if opts.logFile != "" {
		source.name, source.args = "tail", []string{"-n", "0", "-F", opts.logFile}
	} else {
		source.name, source.args = "journalctl", []string{"--no-pager", "-n", "0", "-f", "-u", opts.journalUnit, "-o", "cat"}
	}
	mgr := newManager(opts.window, opts.threshold, opts.banDuration, allowlist, fw, realClock{}, log.Default())
	return serve(ctx, source, mgr, log.Default())
}

func parseAllowlist(value string) ([]netip.Prefix, error) {
	var result []netip.Prefix
	for field := range strings.SplitSeq(value, ",") {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		if addr, err := netip.ParseAddr(field); err == nil {
			result = append(result, netip.PrefixFrom(addr, addr.BitLen()))
			continue
		}
		prefix, err := netip.ParsePrefix(field)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist entry %q: %w", field, err)
		}
		result = append(result, prefix.Masked())
	}
	return result, nil
}
