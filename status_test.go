package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestMetricsAndBlocksEndpoints(t *testing.T) {
	c := &fakeClock{now: time.Unix(1_700_000_000, 0).UTC()}
	m := newManager(time.Minute, 1, time.Minute, nil, &recordingFirewall{}, c, log.New(io.Discard, "", 0))
	addr := netip.MustParseAddr("2001:db8::10")
	if err := m.RecordFailure(t.Context(), addr); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newStatusHandler(m))
	t.Cleanup(srv.Close)

	metricsResp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	metricsBody, err := io.ReadAll(metricsResp.Body)
	metricsResp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	text := string(metricsBody)
	if got, ok := metricValue(text, "gatewarden_blocked_current"); !ok || got != 1 {
		t.Fatalf("blocked current = %d, %v\n%s", got, ok, text)
	}
	if got, ok := metricValue(text, "gatewarden_blocks_total"); !ok || got != 1 {
		t.Fatalf("blocks total = %d, %v", got, ok)
	}
	wantUntil := `gatewarden_block_until_seconds{ip="2001:db8::10"} ` + strconv.FormatInt(c.now.Add(time.Minute).Unix(), 10)
	if !strings.Contains(text, wantUntil) {
		t.Fatalf("metrics missing %s\n%s", wantUntil, text)
	}

	blocks, err := fetchBlocks(t.Context(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || blocks[0].IP != addr.String() || !blocks[0].Until.Equal(c.now.Add(time.Minute)) {
		t.Fatalf("blocks = %+v", blocks)
	}
	var out strings.Builder
	if err := printBlocks(&out, blocks); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), addr.String()) || !strings.Contains(out.String(), "temporary") {
		t.Fatalf("printed %q", out.String())
	}
	out.Reset()
	if err := printBlocks(&out, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "no blocked addresses\n" {
		t.Fatalf("empty print = %q", out.String())
	}

	unblock, err := http.Post(srv.URL+"/unblock", "application/json", strings.NewReader(`{"ip":"192.0.2.1"}`))
	if err != nil {
		t.Fatal(err)
	}
	unblock.Body.Close()
	if unblock.StatusCode != http.StatusNotFound {
		t.Fatalf("metrics port unblock status = %d", unblock.StatusCode)
	}
}

func TestPermanentMetricsAndControlSocket(t *testing.T) {
	c := &fakeClock{now: time.Unix(1_800_000_000, 0).UTC()}
	fw := &recordingFirewall{}
	m := newManager(time.Minute, 1, time.Minute, nil, fw, c, log.New(io.Discard, "", 0))
	m.configurePermanent(1, time.Hour, "")
	addr := netip.MustParseAddr("192.0.2.40")
	if err := m.RecordFailure(t.Context(), addr); err != nil {
		t.Fatal(err)
	}
	var metrics bytes.Buffer
	writeMetrics(&metrics, m.status())
	text := metrics.String()
	if got, ok := metricValue(text, "gatewarden_permanent_current"); !ok || got != 1 {
		t.Fatalf("permanent current = %d, %v\n%s", got, ok, text)
	}
	if got, ok := metricValue(text, "gatewarden_blocked_current"); !ok || got != 1 {
		t.Fatalf("blocked current = %d, %v", got, ok)
	}
	if strings.Contains(text, "gatewarden_block_until_seconds{") {
		t.Fatalf("permanent address published an expiry\n%s", text)
	}
	if !strings.Contains(text, "gatewarden_permanent{ip=\"192.0.2.40\"} 1\n") {
		t.Fatalf("metrics missing permanent series\n%s", text)
	}

	path := shortSocketPath(t)
	ln, err := listenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: newControlHandler(m)}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	blocks, err := fetchBlocksWith(t.Context(), socketClient(path), "http://gatewarden")
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || !blocks[0].Permanent || !blocks[0].Until.IsZero() {
		t.Fatalf("socket blocks = %+v", blocks)
	}
	if err := pardonRemote(t.Context(), path, addr); err != nil {
		t.Fatal(err)
	}
	blocks, err = fetchBlocksWith(t.Context(), socketClient(path), "http://gatewarden")
	if err != nil || len(blocks) != 0 {
		t.Fatalf("after pardon = %+v, %v", blocks, err)
	}
	if len(fw.unblocked) != 1 {
		t.Fatalf("unblocks = %d", len(fw.unblocked))
	}
}

func TestListenControlReplacesStaleSocket(t *testing.T) {
	path := filepath.Join(shortSocketDir(t), "nested", "gw.sock")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("stale"), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := listenControl(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o", info.Mode().Perm())
	}
}

func shortSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "gw")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func shortSocketPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(shortSocketDir(t), "gw.sock")
}

func TestSocketUnavailableDetectsDialErrors(t *testing.T) {
	err := fmt.Errorf("pardon %s: %w", "192.0.2.1", &net.OpError{Op: "dial", Net: "unix", Err: errors.New("connect: connection refused")})
	if !socketUnavailable(err) {
		t.Fatal("dial error was treated as an application error")
	}
	if socketUnavailable(errors.New("pardon 192.0.2.1: address is not blocked")) {
		t.Fatal("application error was treated as a dial error")
	}
}

func TestBlocksFromStateListsPermanentBans(t *testing.T) {
	c := &fakeClock{now: time.Unix(7_000, 0).UTC()}
	path := filepath.Join(t.TempDir(), "state.json")
	m := newManager(time.Minute, 1, time.Minute, nil, &recordingFirewall{}, c, log.New(io.Discard, "", 0))
	m.configurePermanent(1, time.Hour, path)
	addr := netip.MustParseAddr("192.0.2.41")
	if err := m.RecordFailure(t.Context(), addr); err != nil {
		t.Fatal(err)
	}
	blocks, err := blocksFromState(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(blocks) != 1 || blocks[0].IP != addr.String() || !blocks[0].Permanent {
		t.Fatalf("stored blocks = %+v", blocks)
	}
	var out strings.Builder
	if err := printBlocks(&out, blocks); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "permanent") {
		t.Fatalf("printed %q", out.String())
	}
}

func TestSessionsEndpointAndMetrics(t *testing.T) {
	c := &fakeClock{now: time.Unix(1_700_000_100, 0).UTC()}
	m := newManager(time.Minute, 1, time.Minute, nil, &recordingFirewall{}, c, log.New(io.Discard, "", 0))
	since := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	m.openSession(sessionEvent{user: "root", addr: netip.MustParseAddr("192.0.2.10"), port: 54321, pid: 42, when: since})
	var metrics bytes.Buffer
	writeMetrics(&metrics, m.status())
	text := metrics.String()
	if got, ok := metricValue(text, "gatewarden_sessions_current"); !ok || got != 1 {
		t.Fatalf("sessions current = %d, %v\n%s", got, ok, text)
	}
	want := `gatewarden_session_since_seconds{user="root",ip="192.0.2.10",port="54321"} ` + strconv.FormatInt(since.Unix(), 10)
	if !strings.Contains(text, want) {
		t.Fatalf("metrics missing %s\n%s", want, text)
	}

	srv := httptest.NewServer(newStatusHandler(m))
	t.Cleanup(srv.Close)
	resp, err := http.Get(srv.URL + "/sessions")
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(body), `"user":"root"`) || !strings.Contains(string(body), `"port":54321`) || !strings.Contains(string(body), `"pid":42`) {
		t.Fatalf("sessions status=%d body=%s", resp.StatusCode, body)
	}
	sessions, err := fetchSessionsWith(t.Context(), http.DefaultClient, srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := printSessions(&out, sessions); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "root") || !strings.Contains(out.String(), "42") || !strings.Contains(out.String(), "PID") || !strings.Contains(out.String(), since.Format(time.RFC3339)) {
		t.Fatalf("printed %q", out.String())
	}
	out.Reset()
	if err := printSessions(&out, nil); err != nil {
		t.Fatal(err)
	}
	if out.String() != "no open ssh sessions\n" {
		t.Fatalf("empty print = %q", out.String())
	}
	if err := runSessions([]string{"-socket", filepath.Join(shortSocketDir(t), "missing.sock")}); err == nil || !strings.Contains(err.Error(), "open SSH sessions are known only while gatewarden is running") {
		t.Fatal(err)
	}
}

func TestPrometheusLabelEscapesQuotes(t *testing.T) {
	if got := prometheusLabel(`a"b\c`); got != `"a\"b\\c"` {
		t.Fatalf("label = %s", got)
	}
}

func metricValue(text, name string) (int64, bool) {
	prefix := name + " "
	for line := range strings.SplitSeq(text, "\n") {
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimPrefix(line, prefix), 10, 64)
		return value, err == nil
	}
	return 0, false
}
