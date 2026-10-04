package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type options struct {
	logFile         string
	journalUnit     string
	window          time.Duration
	threshold       int
	banDuration     time.Duration
	allowlist       string
	iface           string
	metricsAddr     string
	permanentAfter  int
	permanentWindow time.Duration
	stateFile       string
	socketPath      string
	dryRun          bool
}

func main() {
	if err := run(); err != nil {
		log.Printf("gatewarden: %v", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "blocks":
			return runBlocks(os.Args[2:])
		case "unblock":
			return runUnblock(os.Args[2:])
		}
	}
	permanentAfter, err := configuredInt("GATEWARDEN_PERMANENT_AFTER", os.Getenv("GATEWARDEN_PERMANENT_AFTER"), 3)
	if err != nil {
		return err
	}
	permanentWindow, err := configuredDuration("GATEWARDEN_PERMANENT_WINDOW", os.Getenv("GATEWARDEN_PERMANENT_WINDOW"), 24*time.Hour)
	if err != nil {
		return err
	}
	var opts options
	flag.StringVar(&opts.logFile, "log-file", "", "follow this SSH log file instead of journald")
	flag.StringVar(&opts.journalUnit, "journal-unit", configuredValue(os.Getenv("GATEWARDEN_JOURNAL_UNIT"), "ssh"), "systemd unit to follow; GATEWARDEN_JOURNAL_UNIT is used when this flag is omitted")
	flag.DurationVar(&opts.window, "window", 5*time.Minute, "rolling failure window")
	flag.IntVar(&opts.threshold, "threshold", 5, "failures in the window before blocking")
	flag.DurationVar(&opts.banDuration, "ban-duration", 15*time.Minute, "duration of a block")
	flag.IntVar(&opts.permanentAfter, "permanent-after", permanentAfter, "temporary bans within -permanent-window before a permanent block; 0 disables permanent bans; GATEWARDEN_PERMANENT_AFTER is used when this flag is omitted")
	flag.DurationVar(&opts.permanentWindow, "permanent-window", permanentWindow, "how far back a ban still counts toward a permanent block; GATEWARDEN_PERMANENT_WINDOW is used when this flag is omitted")
	flag.StringVar(&opts.allowlist, "allowlist", configuredValue(os.Getenv("GATEWARDEN_ALLOWLIST"), "127.0.0.0/8,::1/128"), "comma-separated IP addresses or CIDRs never blocked; GATEWARDEN_ALLOWLIST is used when this flag is omitted")
	flag.StringVar(&opts.iface, "interface", configuredValue(os.Getenv("GATEWARDEN_INTERFACE"), ""), "Ethernet ingress interface for the eBPF/XDP block map; GATEWARDEN_INTERFACE is used when this flag is omitted")
	flag.StringVar(&opts.metricsAddr, "metrics-addr", configuredValue(os.Getenv("GATEWARDEN_METRICS_ADDR"), defaultMetricsAddr), "host:port for /metrics and /blocks; GATEWARDEN_METRICS_ADDR is used when this flag is omitted")
	flag.StringVar(&opts.stateFile, "state-file", configuredValue(os.Getenv("GATEWARDEN_STATE_FILE"), defaultStatePath), "permanent bans and recent ban times; GATEWARDEN_STATE_FILE is used when this flag is omitted")
	flag.StringVar(&opts.socketPath, "socket", configuredValue(os.Getenv("GATEWARDEN_SOCKET"), defaultSocketPath), "unix socket for blocks and unblock; GATEWARDEN_SOCKET is used when this flag is omitted")
	flag.BoolVar(&opts.dryRun, "dry-run", false, "log block changes without opening BPF objects")
	flag.Parse()
	if opts.window <= 0 || opts.threshold <= 0 || opts.banDuration <= 0 {
		return errors.New("window, threshold, and ban-duration must be positive")
	}
	if opts.permanentAfter < 0 {
		return errors.New("permanent-after must be zero or positive")
	}
	if opts.permanentAfter > 0 && opts.permanentWindow <= 0 {
		return errors.New("permanent-window must be positive")
	}
	if opts.stateFile == "" || opts.socketPath == "" {
		return errors.New("state-file and socket must be set")
	}
	allowlist, err := parseAllowlist(opts.allowlist)
	if err != nil {
		return err
	}
	runner := execRunner{}
	fw, err := newEBPFFirewall(opts.iface, opts.dryRun, log.Default())
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
	mgr.configurePermanent(opts.permanentAfter, opts.permanentWindow, opts.stateFile)
	if err := mgr.load(); err != nil {
		return err
	}
	if err := mgr.applyPermanent(ctx); err != nil {
		return err
	}
	metricsLn, err := net.Listen("tcp", opts.metricsAddr)
	if err != nil {
		return fmt.Errorf("listen for metrics on %s: %w", opts.metricsAddr, err)
	}
	controlLn, err := listenControl(opts.socketPath)
	if err != nil {
		metricsLn.Close()
		return err
	}
	metrics := serveHTTP("metrics", metricsLn, newStatusHandler(mgr))
	control := serveHTTP("control", controlLn, newControlHandler(mgr))
	defer func() {
		stopServer("control", control)
		stopServer("metrics", metrics)
		if err := os.Remove(opts.socketPath); err != nil && !errors.Is(err, os.ErrNotExist) {
			log.Printf("gatewarden: remove socket: %v", err)
		}
	}()
	log.Printf("metrics: listening on %s", opts.metricsAddr)
	log.Printf("control: listening on %s", opts.socketPath)
	return serve(ctx, source, mgr, log.Default())
}

func serveHTTP(name string, ln net.Listener, handler http.Handler) *http.Server {
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("gatewarden: %s: %v", name, err)
		}
	}()
	return srv
}

func stopServer(name string, srv *http.Server) {
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("gatewarden: stop %s: %v", name, err)
	}
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

func configuredValue(value, fallback string) string {
	if v := strings.TrimSpace(value); v != "" {
		return v
	}
	return strings.TrimSpace(fallback)
}

func configuredInt(name, value string, fallback int) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return n, nil
}

func configuredDuration(name, value string, fallback time.Duration) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	return d, nil
}
