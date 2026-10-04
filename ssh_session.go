package main

import (
	"cmp"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
)

const (
	sshEventOpen  = 1
	sshEventClose = 2
	connValueLen  = 24
	sshEventLen   = 24
)

// sessionEvent is one SSH connection observed from a tracepoint or /proc.
// when is the process start when it is known. The zero time means "now".
type sessionEvent struct {
	user string
	addr netip.Addr
	port uint16
	pid  int
	when time.Time
}

// conn value, 24 bytes: family at 0 (4 or 6), port in network order at 2,
// address at 4. event, 24 bytes: kind at 0, family at 1, port at 2, pid at 4,
// address at 8. Both are little-endian except the port bytes.
func encodeConnValue(addr netip.Addr, port uint16) [connValueLen]byte {
	var raw [connValueLen]byte
	putConn(raw[:], addr, port)
	return raw
}

func putConn(raw []byte, addr netip.Addr, port uint16) {
	addr = addr.Unmap()
	if addr.Is4() {
		raw[0] = 4
		ip := addr.As4()
		copy(raw[4:8], ip[:])
	} else if addr.Is6() {
		raw[0] = 6
		ip := addr.As16()
		copy(raw[4:20], ip[:])
	}
	raw[2] = byte(port >> 8)
	raw[3] = byte(port)
}

func decodeConnValue(raw []byte) (netip.Addr, uint16, bool) {
	if len(raw) < connValueLen {
		return netip.Addr{}, 0, false
	}
	addr, port, ok := takeAddr(raw[0], raw[2:4], raw[4:20])
	return addr, port, ok
}

func decodeSSHEvent(raw []byte) (kind byte, pid int, addr netip.Addr, port uint16, ok bool) {
	if len(raw) < sshEventLen {
		return 0, 0, netip.Addr{}, 0, false
	}
	kind = raw[0]
	if kind != sshEventOpen && kind != sshEventClose {
		return 0, 0, netip.Addr{}, 0, false
	}
	addr, port, ok = takeAddr(raw[1], raw[2:4], raw[8:24])
	if !ok {
		return 0, 0, netip.Addr{}, 0, false
	}
	pid = int(binary.LittleEndian.Uint32(raw[4:8]))
	return kind, pid, addr, port, true
}

func takeAddr(family byte, portRaw, addrRaw []byte) (netip.Addr, uint16, bool) {
	port := uint16(portRaw[0])<<8 | uint16(portRaw[1])
	var addr netip.Addr
	switch family {
	case 4:
		addr = netip.AddrFrom4([4]byte(addrRaw[:4]))
	case 6:
		addr = netip.AddrFrom16([16]byte(addrRaw[:16]))
	default:
		return netip.Addr{}, 0, false
	}
	return addr.Unmap(), port, true
}

func usablePeer(addr netip.Addr, port uint16) bool {
	addr = addr.Unmap()
	return port != 0 && addr.IsValid() && !addr.IsUnspecified() && !addr.IsMulticast()
}

func isSSHDaemon(comm string) bool {
	comm = strings.TrimRight(comm, "\x00\n")
	return comm == "sshd" || strings.HasPrefix(comm, "sshd-")
}

// parseLoginUID accepts a real uid. Empty, -1, and the unsigned form of -1
// mean the kernel has not recorded a login. uid 0 is root and is valid.
func parseLoginUID(text string) (uint32, bool) {
	text = strings.TrimSpace(text)
	if text == "" || text == "-1" {
		return 0, false
	}
	value, err := strconv.ParseUint(text, 10, 32)
	if err != nil || value == 4294967295 {
		return 0, false
	}
	return uint32(value), true
}

var lookupUID = func(uid string) (string, error) {
	account, err := user.LookupId(uid)
	if err != nil {
		return "", err
	}
	return account.Username, nil
}

func userFromUID(uid uint32) string {
	text := strconv.FormatUint(uint64(uid), 10)
	name, err := lookupUID(text)
	if err != nil || name == "" {
		return text
	}
	return name
}

type tcpEndpoint struct {
	inode uint64
	addr  netip.Addr
	port  uint16
}

// parseProcNetTCP returns established peers from /proc/net/tcp or tcp6.
// IPv4 and IPv6 addresses in those files are little-endian hex words.
func parseProcNetTCP(text string) []tcpEndpoint {
	var peers []tcpEndpoint
	for line := range strings.SplitSeq(text, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 || fields[0] == "sl" || fields[3] != "01" {
			continue
		}
		addr, port, ok := parseProcHexAddr(fields[2])
		if !ok {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		peers = append(peers, tcpEndpoint{inode: inode, addr: addr, port: port})
	}
	return peers
}

func parseProcHexAddr(field string) (netip.Addr, uint16, bool) {
	host, portText, ok := strings.Cut(field, ":")
	if !ok {
		return netip.Addr{}, 0, false
	}
	portValue, err := strconv.ParseUint(portText, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, false
	}
	var addr netip.Addr
	switch len(host) {
	case 8:
		addr, ok = parseLEWord(host)
	case 32:
		addr, ok = parseLEIPv6(host)
	default:
		return netip.Addr{}, 0, false
	}
	if !ok {
		return netip.Addr{}, 0, false
	}
	return addr, uint16(portValue), true
}

func parseLEWord(hex string) (netip.Addr, bool) {
	value, err := strconv.ParseUint(hex, 16, 32)
	if err != nil {
		return netip.Addr{}, false
	}
	return netip.AddrFrom4([4]byte{byte(value), byte(value >> 8), byte(value >> 16), byte(value >> 24)}), true
}

func parseLEIPv6(hex string) (netip.Addr, bool) {
	var raw [16]byte
	for i := range 4 {
		word, ok := parseLEWord(hex[i*8 : (i+1)*8])
		if !ok {
			return netip.Addr{}, false
		}
		part := word.As4()
		copy(raw[i*4:(i+1)*4], part[:])
	}
	return netip.AddrFrom16(raw), true
}

func parseBtime(text string) (int64, bool) {
	for line := range strings.SplitSeq(text, "\n") {
		rest, ok := strings.CutPrefix(line, "btime ")
		if !ok {
			continue
		}
		value, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
		if err != nil {
			return 0, false
		}
		return value, true
	}
	return 0, false
}

// parseProcStart reads field 22 of /proc/<pid>/stat. The command may contain
// spaces, so fields are counted after the last ')'. USER_HZ is 100 on the
// architectures this program runs on.
func parseProcStart(stat string, btime int64) (time.Time, bool) {
	end := strings.LastIndex(stat, ")")
	if end < 0 || end+2 >= len(stat) {
		return time.Time{}, false
	}
	fields := strings.Fields(stat[end+2:])
	if len(fields) < 20 {
		return time.Time{}, false
	}
	ticks, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	const userHZ = 100
	seconds := btime + ticks/userHZ
	nanos := (ticks % userHZ) * (int64(time.Second) / userHZ)
	return time.Unix(seconds, nanos).UTC(), true
}

func fieldOffset(format, field string) (offset, size int, err error) {
	pattern := `(?m)(?:^|[^\w])` + regexp.QuoteMeta(field) + `(?:\[\d+\])?;\s*offset:(\d+);\s*size:(\d+);`
	match := regexp.MustCompile(pattern).FindStringSubmatch(format)
	if match == nil {
		return 0, 0, fmt.Errorf("tracepoint field %s not found", field)
	}
	offset, err = strconv.Atoi(match[1])
	if err != nil {
		return 0, 0, err
	}
	size, err = strconv.Atoi(match[2])
	if err != nil {
		return 0, 0, err
	}
	return offset, size, nil
}

type sshProc struct {
	PID      int
	Comm     string
	LoginUID uint32
	HasLogin bool
	Addr     netip.Addr
	Port     uint16
	Started  time.Time
}

func scanSSHProcs(root string) ([]sshProc, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", root, err)
	}
	btime, btimeOK := readBtime(filepath.Join(root, "stat"))
	var found []sshProc
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		dir := filepath.Join(root, entry.Name())
		commRaw, err := os.ReadFile(filepath.Join(dir, "comm"))
		if err != nil {
			continue
		}
		comm := strings.TrimRight(string(commRaw), "\n\x00")
		if !isSSHDaemon(comm) {
			continue
		}
		uid, hasLogin := readLoginUID(filepath.Join(dir, "loginuid"))
		var started time.Time
		if btimeOK {
			if statRaw, err := os.ReadFile(filepath.Join(dir, "stat")); err == nil {
				started, _ = parseProcStart(string(statRaw), btime)
			}
		}
		peers, err := processPeers(dir)
		if err != nil {
			continue
		}
		for _, peer := range peers {
			if !usablePeer(peer.addr, peer.port) {
				continue
			}
			found = append(found, sshProc{
				PID: pid, Comm: comm, LoginUID: uid, HasLogin: hasLogin,
				Addr: peer.addr.Unmap(), Port: peer.port, Started: started,
			})
		}
	}
	return dedupeSSHProcs(found), nil
}

func readProcStart(root string, pid int) (time.Time, bool) {
	btime, ok := readBtime(filepath.Join(root, "stat"))
	if !ok {
		return time.Time{}, false
	}
	stat, err := os.ReadFile(filepath.Join(root, strconv.Itoa(pid), "stat"))
	if err != nil {
		return time.Time{}, false
	}
	return parseProcStart(string(stat), btime)
}

func procAlive(root string, pid int) bool {
	_, err := os.Stat(filepath.Join(root, strconv.Itoa(pid)))
	return !os.IsNotExist(err)
}

func readBtime(path string) (int64, bool) {
	text, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	return parseBtime(string(text))
}

func readLoginUID(path string) (uint32, bool) {
	text, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	return parseLoginUID(string(text))
}

var socketLink = regexp.MustCompile(`^socket:\[(\d+)\]$`)

func processPeers(dir string) ([]tcpEndpoint, error) {
	fdEntries, err := os.ReadDir(filepath.Join(dir, "fd"))
	if err != nil {
		return nil, err
	}
	want := map[uint64]struct{}{}
	for _, entry := range fdEntries {
		target, err := os.Readlink(filepath.Join(dir, "fd", entry.Name()))
		if err != nil {
			continue
		}
		match := socketLink.FindStringSubmatch(target)
		if match == nil {
			continue
		}
		inode, err := strconv.ParseUint(match[1], 10, 64)
		if err != nil {
			continue
		}
		want[inode] = struct{}{}
	}
	if len(want) == 0 {
		return nil, nil
	}
	var peers []tcpEndpoint
	for _, name := range []string{"net/tcp", "net/tcp6"} {
		text, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return nil, err
		}
		for _, peer := range parseProcNetTCP(string(text)) {
			if _, ok := want[peer.inode]; ok {
				peers = append(peers, peer)
			}
		}
	}
	return peers, nil
}

func dedupeSSHProcs(in []sshProc) []sshProc {
	best := make(map[sessionKey]sshProc)
	for _, proc := range in {
		key := sessionKey{addr: proc.Addr, port: proc.Port}
		prev, ok := best[key]
		if !ok || preferSSHProc(proc, prev) {
			best[key] = proc
		}
	}
	out := make([]sshProc, 0, len(best))
	for _, proc := range best {
		out = append(out, proc)
	}
	slices.SortFunc(out, func(a, b sshProc) int {
		if c := cmp.Compare(a.Addr.String(), b.Addr.String()); c != 0 {
			return c
		}
		return cmp.Compare(a.Port, b.Port)
	})
	return out
}

func preferSSHProc(cand, current sshProc) bool {
	if cand.HasLogin != current.HasLogin {
		return cand.HasLogin
	}
	candSession := cand.Comm == "sshd-session"
	currentSession := current.Comm == "sshd-session"
	if candSession != currentSession {
		return candSession
	}
	return cand.PID < current.PID
}
