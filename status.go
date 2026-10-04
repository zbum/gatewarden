package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"
)

const (
	defaultMetricsAddr = "127.0.0.1:9477"
	defaultSocketPath  = "/run/gatewarden/gatewarden.sock"
	defaultStatePath   = "/var/lib/gatewarden/state.json"
)

type blockView struct {
	IP        string    `json:"ip"`
	Until     time.Time `json:"until,omitzero"`
	Permanent bool      `json:"permanent,omitzero"`
}

func newStatusHandler(m *manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		writeMetrics(w, m.status())
	})
	mux.HandleFunc("GET /blocks", func(w http.ResponseWriter, _ *http.Request) {
		writeBlocks(w, m.status())
	})
	return mux
}

func newControlHandler(m *manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /blocks", func(w http.ResponseWriter, _ *http.Request) {
		writeBlocks(w, m.status())
	})
	mux.HandleFunc("POST /unblock", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		addr, err := netip.ParseAddr(req.IP)
		if err != nil {
			http.Error(w, "invalid ip", http.StatusBadRequest)
			return
		}
		if err := m.Pardon(r.Context(), addr); err != nil {
			status := http.StatusInternalServerError
			if errors.Is(err, errNotBlocked) {
				status = http.StatusNotFound
			}
			http.Error(w, err.Error(), status)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	return mux
}

func writeBlocks(w http.ResponseWriter, snapshot statusSnapshot) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(blockViews(snapshot)); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func blockViews(snapshot statusSnapshot) []blockView {
	views := make([]blockView, 0, len(snapshot.Blocks))
	for _, block := range snapshot.Blocks {
		view := blockView{IP: block.Addr.String(), Permanent: block.Permanent}
		if !block.Permanent {
			view.Until = block.Until.UTC()
		}
		views = append(views, view)
	}
	return views
}

func writeMetrics(w io.Writer, snapshot statusSnapshot) {
	fmt.Fprintf(w, "# HELP gatewarden_blocked_current Addresses currently blocked.\n")
	fmt.Fprintf(w, "# TYPE gatewarden_blocked_current gauge\n")
	fmt.Fprintf(w, "gatewarden_blocked_current %d\n", len(snapshot.Blocks))
	fmt.Fprintf(w, "# HELP gatewarden_blocks_total Blocks applied since the process started.\n")
	fmt.Fprintf(w, "# TYPE gatewarden_blocks_total counter\n")
	fmt.Fprintf(w, "gatewarden_blocks_total %d\n", snapshot.BlocksTotal)
	fmt.Fprintf(w, "# HELP gatewarden_unblocks_total Blocks removed after expiry since the process started.\n")
	fmt.Fprintf(w, "# TYPE gatewarden_unblocks_total counter\n")
	fmt.Fprintf(w, "gatewarden_unblocks_total %d\n", snapshot.UnblocksTotal)
	fmt.Fprintf(w, "# HELP gatewarden_failures_total Counted authentication failures since the process started.\n")
	fmt.Fprintf(w, "# TYPE gatewarden_failures_total counter\n")
	fmt.Fprintf(w, "gatewarden_failures_total %d\n", snapshot.FailuresTotal)
	permanent := 0
	for _, block := range snapshot.Blocks {
		if block.Permanent {
			permanent++
		}
	}
	fmt.Fprintf(w, "# HELP gatewarden_permanent_current Addresses permanently blocked.\n")
	fmt.Fprintf(w, "# TYPE gatewarden_permanent_current gauge\n")
	fmt.Fprintf(w, "gatewarden_permanent_current %d\n", permanent)
	fmt.Fprintf(w, "# HELP gatewarden_block_until_seconds Unix time when a temporary block expires.\n")
	fmt.Fprintf(w, "# TYPE gatewarden_block_until_seconds gauge\n")
	fmt.Fprintf(w, "# HELP gatewarden_permanent 1 while the address is permanently blocked.\n")
	fmt.Fprintf(w, "# TYPE gatewarden_permanent gauge\n")
	for _, block := range snapshot.Blocks {
		label := prometheusLabel(block.Addr.String())
		if block.Permanent {
			fmt.Fprintf(w, "gatewarden_permanent{ip=%s} 1\n", label)
			continue
		}
		fmt.Fprintf(w, "gatewarden_block_until_seconds{ip=%s} %d\n", label, block.Until.UTC().Unix())
	}
}

func prometheusLabel(value string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range value {
		switch r {
		case '\\', '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func runBlocks(args []string) error {
	socket, stateFile, err := controlFlags("blocks", args)
	if err != nil || socket == "" {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	blocks, err := fetchBlocksWith(ctx, socketClient(socket), "http://gatewarden")
	if err != nil {
		if !socketUnavailable(err) {
			return err
		}
		blocks, err = blocksFromState(stateFile)
		if err != nil {
			return err
		}
	}
	return printBlocks(os.Stdout, blocks)
}

func runUnblock(args []string) error {
	fs := flag.NewFlagSet("unblock", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", configuredValue(os.Getenv("GATEWARDEN_SOCKET"), defaultSocketPath), "unix socket of the running gatewarden process")
	stateFile := fs.String("state-file", configuredValue(os.Getenv("GATEWARDEN_STATE_FILE"), defaultStatePath), "ban state file used when the daemon socket is unavailable")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: gatewarden unblock <ip>")
	}
	addr, err := netip.ParseAddr(fs.Arg(0))
	if err != nil {
		return fmt.Errorf("invalid ip %q: %w", fs.Arg(0), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err = pardonRemote(ctx, *socket, addr)
	if err == nil || !socketUnavailable(err) {
		return err
	}
	if fileErr := pardonOffline(*stateFile, addr); fileErr != nil {
		if errors.Is(fileErr, errNotBlocked) {
			return fmt.Errorf("daemon socket %s is unavailable and %s is not recorded in %s", *socket, addr, *stateFile)
		}
		return fileErr
	}
	return nil
}

func controlFlags(name string, args []string) (string, string, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	socket := fs.String("socket", configuredValue(os.Getenv("GATEWARDEN_SOCKET"), defaultSocketPath), "unix socket of the running gatewarden process")
	stateFile := fs.String("state-file", configuredValue(os.Getenv("GATEWARDEN_STATE_FILE"), defaultStatePath), "ban state file used when the daemon socket is unavailable")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return "", "", nil
		}
		return "", "", err
	}
	return *socket, *stateFile, nil
}

func socketUnavailable(err error) bool {
	_, ok := errors.AsType[*net.OpError](err)
	return ok
}

func listenControl(path string) (net.Listener, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("remove stale socket: %w", err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("protect socket: %w", err)
	}
	return ln, nil
}

func socketClient(path string) *http.Client {
	return &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dialer net.Dialer
			return dialer.DialContext(ctx, "unix", path)
		},
	}}
}

func fetchBlocks(ctx context.Context, baseURL string) ([]blockView, error) {
	return fetchBlocksWith(ctx, http.DefaultClient, baseURL)
}

func fetchBlocksWith(ctx context.Context, client *http.Client, baseURL string) ([]blockView, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(baseURL, "/")+"/blocks", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("read blocks from %s: %w", baseURL, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("read blocks from %s: %s", baseURL, strings.TrimSpace(string(body)))
	}
	var blocks []blockView
	if err := json.Unmarshal(body, &blocks); err != nil {
		return nil, fmt.Errorf("decode blocks from %s: %w", baseURL, err)
	}
	return blocks, nil
}

func pardonRemote(ctx context.Context, socket string, addr netip.Addr) error {
	body, err := json.Marshal(struct {
		IP string `json:"ip"`
	}{IP: addr.String()})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://gatewarden/unblock", strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := socketClient(socket).Do(req)
	if err != nil {
		return fmt.Errorf("pardon %s: %w", addr, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	text, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	return fmt.Errorf("pardon %s: %s", addr, strings.TrimSpace(string(text)))
}

func printBlocks(w io.Writer, blocks []blockView) error {
	if len(blocks) == 0 {
		_, err := fmt.Fprintln(w, "no blocked addresses")
		return err
	}
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "IP\tEXPIRES\tKIND")
	for _, block := range blocks {
		expires, kind := block.Until.UTC().Format(time.RFC3339), "temporary"
		if block.Permanent {
			expires, kind = "permanent", "permanent"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", block.IP, expires, kind)
	}
	return tw.Flush()
}
