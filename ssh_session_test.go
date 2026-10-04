package main

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestConnValueAndEventRoundTrip(t *testing.T) {
	cases := []struct {
		addr string
		port uint16
	}{
		{"192.0.2.10", 54321},
		{"2001:db8::5", 50000},
		{"::ffff:192.0.2.10", 22},
	}
	for _, tt := range cases {
		addr := netip.MustParseAddr(tt.addr).Unmap()
		raw := encodeConnValue(netip.MustParseAddr(tt.addr), tt.port)
		got, port, ok := decodeConnValue(raw[:])
		if !ok || got != addr || port != tt.port {
			t.Fatalf("conn %s = %s %d %v", tt.addr, got, port, ok)
		}
		var event [sshEventLen]byte
		event[0] = sshEventOpen
		event[1] = raw[0]
		event[2], event[3] = raw[2], raw[3]
		binary.LittleEndian.PutUint32(event[4:8], 42)
		copy(event[8:], raw[4:20])
		kind, pid, got, port, ok := decodeSSHEvent(event[:])
		if !ok || kind != sshEventOpen || pid != 42 || got != addr || port != tt.port {
			t.Fatalf("event %s = %d %d %s %d %v", tt.addr, kind, pid, got, port, ok)
		}
	}
	var mapped [sshEventLen]byte
	mapped[0] = sshEventClose
	mapped[1] = 6
	mapped[2], mapped[3] = 0, 22
	ip := netip.MustParseAddr("::ffff:192.0.2.10").As16()
	copy(mapped[8:], ip[:])
	kind, _, got, port, ok := decodeSSHEvent(mapped[:])
	if !ok || kind != sshEventClose || got.String() != "192.0.2.10" || port != 22 || got.Is6() {
		t.Fatalf("mapped event = %d %s %d %v", kind, got, port, ok)
	}
	if _, _, _, _, ok := decodeSSHEvent([]byte{9}); ok {
		t.Fatal("short event was accepted")
	}
	if _, _, _, _, ok := decodeSSHEvent(make([]byte, sshEventLen)); ok {
		t.Fatal("zero event was accepted")
	}
}

func TestLoginUIDAndDaemonName(t *testing.T) {
	if _, ok := parseLoginUID(""); ok {
		t.Fatal("empty loginuid was accepted")
	}
	if _, ok := parseLoginUID("-1\n"); ok {
		t.Fatal("unset loginuid was accepted")
	}
	if _, ok := parseLoginUID("4294967295"); ok {
		t.Fatal("unsigned unset loginuid was accepted")
	}
	uid, ok := parseLoginUID("0\n")
	if !ok || uid != 0 {
		t.Fatalf("root loginuid = %d %v", uid, ok)
	}
	uid, ok = parseLoginUID("1000")
	if !ok || uid != 1000 {
		t.Fatalf("loginuid = %d %v", uid, ok)
	}
	for _, comm := range []string{"sshd", "sshd\n", "sshd-session", "sshd-auth"} {
		if !isSSHDaemon(comm) {
			t.Fatalf("%q was rejected", comm)
		}
	}
	for _, comm := range []string{"sshdfoo", "ssh", "nginx"} {
		if isSSHDaemon(comm) {
			t.Fatalf("%q was accepted", comm)
		}
	}
}

func TestUserFromUIDFallsBackToNumber(t *testing.T) {
	original := lookupUID
	t.Cleanup(func() { lookupUID = original })
	lookupUID = func(string) (string, error) { return "", errors.New("missing") }
	if got := userFromUID(1000); got != "1000" {
		t.Fatalf("fallback user = %s", got)
	}
	lookupUID = func(string) (string, error) { return "ada", nil }
	if got := userFromUID(1000); got != "ada" {
		t.Fatalf("named user = %s", got)
	}
}

func TestParseProcNetAndStart(t *testing.T) {
	text := "" +
		"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:0016 0A0200C0:D431 01 00000000:00000000 00:00000000 00000000     0        0 100 1 0000000000000000 20 0 0 10 0\n" +
		"   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 200 1 0000000000000000 20 0 0 10 0\n" +
		"   2: 00000000000000000000000000000000:0016 B80D0120000000000000000005000000:C350 01 00000000:00000000 00:00000000 00000000     0        0 300 1 0000000000000000 20 0 0 10 0\n"
	peers := parseProcNetTCP(text)
	if len(peers) != 2 {
		t.Fatalf("peers = %+v", peers)
	}
	if peers[0].inode != 100 || peers[0].port != 54321 || peers[0].addr.String() != "192.0.2.10" {
		t.Fatalf("ipv4 peer = %+v", peers[0])
	}
	if peers[1].inode != 300 || peers[1].port != 50000 || peers[1].addr.String() != "2001:db8::5" {
		t.Fatalf("ipv6 peer = %+v", peers[1])
	}
	started, ok := parseProcStart("42 (sshd: root@pts) S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 500\n", 1_700_000_000)
	want := time.Unix(1_700_000_005, 0).UTC()
	if !ok || !started.Equal(want) {
		t.Fatalf("start = %s %v, want %s", started, ok, want)
	}
	if _, ok := parseBtime("cpu 1\nbtime 1700000000\n"); !ok {
		t.Fatal("btime was not read")
	}
}

func TestFieldOffsetIgnoresLongerNames(t *testing.T) {
	format := "" +
		"field:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n" +
		"field:pid_t parent_pid;\toffset:24;\tsize:4;\tsigned:1;\n" +
		"field:pid_t child_pid;\toffset:44;\tsize:4;\tsigned:1;\n" +
		"field:pid_t pid;\toffset:36;\tsize:4;\tsigned:1;\n" +
		"field:unsigned long args[6];\toffset:16;\tsize:48;\tsigned:0;\n"
	offset, size, err := fieldOffset(format, "pid")
	if err != nil || offset != 36 || size != 4 {
		t.Fatalf("pid = %d %d %v", offset, size, err)
	}
	offset, size, err = fieldOffset(format, "parent_pid")
	if err != nil || offset != 24 || size != 4 {
		t.Fatalf("parent_pid = %d %d %v", offset, size, err)
	}
	offset, size, err = fieldOffset(format, "args")
	if err != nil || offset != 16 || size != 48 {
		t.Fatalf("args = %d %d %v", offset, size, err)
	}
	if _, _, err := fieldOffset(format, "missing"); err == nil {
		t.Fatal("missing field was found")
	}
}

func TestScanSSHProcsPrefersAuthenticatedSession(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "stat"), []byte("btime 1700000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeProc := func(pid, comm, login string, ticks int, tcpName, tcp string, links map[string]string) {
		t.Helper()
		dir := filepath.Join(root, pid)
		if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Join(dir, "net"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "loginuid"), []byte(login+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		stat := pid + " (" + comm + ") S 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 20 0 1 0 " + strconv.Itoa(ticks) + "\n"
		if err := os.WriteFile(filepath.Join(dir, "stat"), []byte(stat), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "net", tcpName), []byte(tcp), 0o644); err != nil {
			t.Fatal(err)
		}
		for name, target := range links {
			if err := os.Symlink(target, filepath.Join(dir, "fd", name)); err != nil {
				t.Fatal(err)
			}
		}
	}
	v4 := "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n" +
		"   0: 0100007F:0016 0A0200C0:D431 01 00000000:00000000 00:00000000 00000000 0 0 100 1 0 20 0 0 10 0\n" +
		"   1: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000 0 0 999 1 0 20 0 0 10 0\n"
	writeProc("10", "sshd", "4294967295", 100, "tcp", v4, map[string]string{"3": "socket:[100]", "4": "socket:[999]", "0": "/dev/null"})
	writeProc("20", "sshd-session", "1000", 200, "tcp",
		"   0: 0100007F:0016 0A0200C0:D431 01 00000000:00000000 00:00000000 00000000 0 0 101 1 0 20 0 0 10 0\n",
		map[string]string{"3": "socket:[101]"})
	writeProc("30", "sshdfoo", "1000", 100, "tcp", v4, map[string]string{"3": "socket:[100]"})
	writeProc("40", "nginx", "0", 100, "tcp", v4, map[string]string{"3": "socket:[100]"})
	writeProc("50", "sshd", "0", 300, "tcp",
		"   0: 0100007F:0016 0B0200C0:0016 01 00000000:00000000 00:00000000 00000000 0 0 300 1 0 20 0 0 10 0\n"+
			"   1: 0100007F:0016 00000000:3039 01 00000000:00000000 00:00000000 00000000 0 0 301 1 0 20 0 0 10 0\n",
		map[string]string{"3": "socket:[300]", "4": "socket:[301]"})
	v6 := "   0: 00000000000000000000000000000000:0016 B80D0120000000000000000005000000:C350 01 00000000:00000000 00:00000000 00000000 0 0 400 1 0 20 0 0 10 0\n"
	writeProc("60", "sshd-session", "4294967295", 400, "tcp6", v6, map[string]string{"5": "socket:[400]"})
	writeProc("70", "sshd", "4294967295", 100, "tcp6",
		"   0: 00000000000000000000000000000000:0016 B80D0120000000000000000005000000:C350 01 00000000:00000000 00:00000000 00000000 0 0 401 1 0 20 0 0 10 0\n",
		map[string]string{"5": "socket:[401]"})

	got, err := scanSSHProcs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("procs = %+v", got)
	}
	if got[0].Addr.String() != "192.0.2.10" || got[0].Port != 54321 || got[0].PID != 20 || !got[0].HasLogin || got[0].LoginUID != 1000 {
		t.Fatalf("authenticated session = %+v", got[0])
	}
	if !got[0].Started.Equal(time.Unix(1_700_000_002, 0).UTC()) {
		t.Fatalf("started = %s", got[0].Started)
	}
	if got[1].Addr.String() != "192.0.2.11" || got[1].Port != 22 || got[1].PID != 50 || got[1].LoginUID != 0 || !got[1].HasLogin {
		t.Fatalf("root session = %+v", got[1])
	}
	if got[2].Addr.String() != "2001:db8::5" || got[2].Port != 50000 || got[2].PID != 60 || got[2].HasLogin {
		t.Fatalf("ipv6 session = %+v", got[2])
	}
}
