//go:build linux

package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"sync"
)

const sshPollEvery = 200 * time.Millisecond

type sshPeer struct {
	addr netip.Addr
	port uint16
	when time.Time
}

type sshWatch struct {
	mu         sync.Mutex
	procRoot   string
	attached   []string
	events     *ebpf.Map
	acceptPtrs *ebpf.Map
	pend       *ebpf.Map
	conns      *ebpf.Map
	reader     *ringbuf.Reader
	links      []link.Link
	progs      []*ebpf.Program
	waiting    map[int][]sshPeer
	published  map[int][]sessionKey
}

func startSSHSessions() (sessionWatcher, error) {
	return openSSHWatch()
}

func openSSHWatch() (*sshWatch, error) {
	watch := &sshWatch{
		procRoot:  "/proc",
		waiting:   make(map[int][]sshPeer),
		published: make(map[int][]sessionKey),
	}
	var err error
	defer func() {
		if err != nil {
			watch.Close()
		}
	}()
	watch.events, err = newMap("gw_ssh_events", ebpf.RingBuf, 0, 0, 1<<20)
	if err != nil {
		return nil, err
	}
	watch.acceptPtrs, err = newMap("gw_accept_ptr", ebpf.Hash, 8, 8, 1024)
	if err != nil {
		return nil, err
	}
	watch.pend, err = newMap("gw_ssh_pend", ebpf.Hash, 4, connValueLen, 1024)
	if err != nil {
		return nil, err
	}
	watch.conns, err = newMap("gw_ssh_conn", ebpf.Hash, 4, connValueLen, 4096)
	if err != nil {
		return nil, err
	}
	if err = watch.attachAccept("sys_enter_accept", "sys_exit_accept", "gw_acc_enter", "gw_acc_exit"); err != nil {
		return nil, err
	}
	if err = watch.attachAccept("sys_enter_accept4", "sys_exit_accept4", "gw_a4_enter", "gw_a4_exit"); err != nil {
		return nil, err
	}
	if len(watch.attached) == 0 {
		err = errors.New("attach SSH session tracepoint: accept and accept4 are unavailable")
		return nil, err
	}
	if err = watch.attachSched(); err != nil {
		return nil, err
	}
	watch.reader, err = ringbuf.NewReader(watch.events)
	if err != nil {
		err = fmt.Errorf("attach SSH session tracepoint: %w", err)
		return nil, err
	}
	return watch, nil
}

func newMap(name string, kind ebpf.MapType, key, value, max uint32) (*ebpf.Map, error) {
	spec := &ebpf.MapSpec{Name: name, Type: kind, KeySize: key, ValueSize: value, MaxEntries: max}
	m, err := ebpf.NewMap(spec)
	if err != nil {
		return nil, fmt.Errorf("attach SSH session tracepoint: create %s: %w", name, err)
	}
	return m, nil
}

func (w *sshWatch) attachAccept(enter, exit, enterName, exitName string) error {
	enterFormat, err := traceFormat("syscalls", enter)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("attach SSH session tracepoint: %w", err)
	}
	exitFormat, err := traceFormat("syscalls", exit)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("attach SSH session tracepoint: %w", err)
	}
	argsOff, err := fieldAt(enterFormat, "args", 48)
	if err != nil {
		return err
	}
	retOff, err := fieldAt(exitFormat, "ret", 8)
	if err != nil {
		return err
	}
	enterProg, err := loadTrace(enterName, acceptEnterProgram(w.acceptPtrs.FD(), argsOff+8))
	if err != nil {
		return err
	}
	w.progs = append(w.progs, enterProg)
	exitProg, err := loadTrace(exitName, acceptExitProgram(w.acceptPtrs.FD(), w.pend.FD(), retOff))
	if err != nil {
		return err
	}
	w.progs = append(w.progs, exitProg)
	if err = w.attach("syscalls", enter, enterProg); err != nil {
		return err
	}
	if err = w.attach("syscalls", exit, exitProg); err != nil {
		return err
	}
	return nil
}

func (w *sshWatch) attachSched() error {
	forkFormat, err := traceFormat("sched", "sched_process_fork")
	if err != nil {
		return fmt.Errorf("attach SSH session tracepoint: %w", err)
	}
	exitFormat, err := traceFormat("sched", "sched_process_exit")
	if err != nil {
		return fmt.Errorf("attach SSH session tracepoint: %w", err)
	}
	parentOff, err := fieldAt(forkFormat, "parent_pid", 4)
	if err != nil {
		return err
	}
	childOff, err := fieldAt(forkFormat, "child_pid", 4)
	if err != nil {
		return err
	}
	pidOff, err := fieldAt(exitFormat, "pid", 4)
	if err != nil {
		return err
	}
	forkProg, err := loadTrace("gw_ssh_fork", sessionForkProgram(w.pend.FD(), w.conns.FD(), w.events.FD(), parentOff, childOff))
	if err != nil {
		return err
	}
	w.progs = append(w.progs, forkProg)
	exitProg, err := loadTrace("gw_ssh_exit", sessionExitProgram(w.conns.FD(), w.events.FD(), pidOff))
	if err != nil {
		return err
	}
	w.progs = append(w.progs, exitProg)
	if err = w.attach("sched", "sched_process_fork", forkProg); err != nil {
		return err
	}
	return w.attach("sched", "sched_process_exit", exitProg)
}

func (w *sshWatch) attach(group, name string, prog *ebpf.Program) error {
	lnk, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		return fmt.Errorf("attach SSH session tracepoint: %s/%s: %w", group, name, err)
	}
	w.links = append(w.links, lnk)
	w.attached = append(w.attached, group+"/"+name)
	return nil
}

func loadTrace(name string, ins asm.Instructions) (*ebpf.Program, error) {
	if len(name) > 15 {
		return nil, fmt.Errorf("attach SSH session tracepoint: program name %s is longer than 15", name)
	}
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: name, Type: ebpf.TracePoint, License: "GPL", Instructions: ins})
	if err != nil {
		return nil, fmt.Errorf("attach SSH session tracepoint: load %s: %w", name, err)
	}
	return prog, nil
}

func traceFormat(group, name string) (string, error) {
	var missing error
	for _, root := range []string{"/sys/kernel/tracing/events", "/sys/kernel/debug/tracing/events"} {
		text, err := os.ReadFile(root + "/" + group + "/" + name + "/format")
		if err == nil {
			return string(text), nil
		}
		if errors.Is(err, os.ErrNotExist) {
			missing = err
			continue
		}
		return "", err
	}
	if missing == nil {
		missing = os.ErrNotExist
	}
	return "", missing
}

func (w *sshWatch) Run(ctx context.Context, m *manager, logger *log.Logger) error {
	logger.Printf("ssh sessions: attached %s", strings.Join(w.attached, ", "))
	procs, err := scanSSHProcs(w.procRoot)
	if err != nil {
		logger.Printf("scan ssh sessions: %v", err)
	}
	for _, proc := range procs {
		if err := w.seed(proc); err != nil {
			logger.Printf("seed ssh session pid=%d: %v", proc.PID, err)
		}
		w.note(m, logger, proc.PID, proc.Addr, proc.Port, proc.Started)
	}
	logger.Printf("ssh sessions: %d open after process scan", len(m.status().Sessions))
	nextPoll := time.Now().Add(sshPollEvery)
	for {
		if ctx.Err() != nil {
			return nil
		}
		w.reader.SetDeadline(time.Now().Add(sshPollEvery))
		record, err := w.reader.Read()
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				w.poll(m, logger)
				nextPoll = time.Now().Add(sshPollEvery)
				continue
			}
			if errors.Is(err, ringbuf.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("read ssh session events: %w", err)
		}
		w.handleRecord(record.RawSample, m, logger)
		if !time.Now().Before(nextPoll) {
			w.poll(m, logger)
			nextPoll = time.Now().Add(sshPollEvery)
		}
	}
}

func (w *sshWatch) seed(proc sshProc) error {
	raw := encodeConnValue(proc.Addr, proc.Port)
	return w.conns.Update(uint32(proc.PID), raw, ebpf.UpdateAny)
}

func (w *sshWatch) handleRecord(sample []byte, m *manager, logger *log.Logger) {
	kind, pid, addr, port, ok := decodeSSHEvent(sample)
	if !ok {
		return
	}
	switch kind {
	case sshEventOpen:
		when, _ := readProcStart(w.procRoot, pid)
		w.note(m, logger, pid, addr, port, when)
	case sshEventClose:
		w.forget(m, logger, pid, addr, port)
	}
}

func (w *sshWatch) note(m *manager, logger *log.Logger, pid int, addr netip.Addr, port uint16, when time.Time) {
	addr = addr.Unmap()
	if !usablePeer(addr, port) || pid <= 0 {
		return
	}
	name, ok := w.loginName(pid)
	if !ok {
		w.rememberWaiting(pid, sshPeer{addr: addr, port: port, when: when})
		return
	}
	w.dropWaiting(pid, addr, port)
	session, created := m.openSession(sessionEvent{user: name, addr: addr, port: port, pid: pid, when: when})
	w.rememberPublished(pid, sessionKey{addr: session.Addr, port: session.Port})
	if created {
		logger.Printf("ssh session open user=%s from=%s port=%d pid=%d", session.User, session.Addr, session.Port, session.PID)
	}
}

func (w *sshWatch) loginName(pid int) (string, bool) {
	uid, ok := readLoginUID(filepath.Join(w.procRoot, strconv.Itoa(pid), "loginuid"))
	if !ok {
		return "", false
	}
	return userFromUID(uid), true
}

func (w *sshWatch) poll(m *manager, logger *log.Logger) {
	w.mu.Lock()
	waiting := make(map[int][]sshPeer, len(w.waiting))
	for pid, peers := range w.waiting {
		waiting[pid] = append([]sshPeer(nil), peers...)
	}
	published := make(map[int][]sessionKey, len(w.published))
	for pid, keys := range w.published {
		published[pid] = append([]sessionKey(nil), keys...)
	}
	w.mu.Unlock()
	for pid, peers := range waiting {
		if !procAlive(w.procRoot, pid) {
			w.clearWaiting(pid)
			if err := w.deleteConn(pid); err != nil {
				logger.Printf("drop ssh session pid=%d: %v", pid, err)
			}
			continue
		}
		for _, peer := range peers {
			w.note(m, logger, pid, peer.addr, peer.port, peer.when)
		}
	}
	for pid, keys := range published {
		if procAlive(w.procRoot, pid) {
			continue
		}
		for _, key := range keys {
			w.forget(m, logger, pid, key.addr, key.port)
		}
		if err := w.deleteConn(pid); err != nil {
			logger.Printf("drop ssh session pid=%d: %v", pid, err)
		}
	}
}

func (w *sshWatch) forget(m *manager, logger *log.Logger, pid int, addr netip.Addr, port uint16) {
	addr = addr.Unmap()
	w.mu.Lock()
	w.waiting[pid] = dropPeer(w.waiting[pid], addr, port)
	if len(w.waiting[pid]) == 0 {
		delete(w.waiting, pid)
	}
	w.published[pid] = dropKey(w.published[pid], addr, port)
	if len(w.published[pid]) == 0 {
		delete(w.published, pid)
	}
	w.mu.Unlock()
	if session, closed := m.closeSession(addr, port); closed {
		logger.Printf("ssh session close user=%s from=%s port=%d pid=%d", session.User, session.Addr, session.Port, session.PID)
	}
}

func (w *sshWatch) rememberWaiting(pid int, peer sshPeer) {
	w.mu.Lock()
	defer w.mu.Unlock()
	peers := dropPeer(w.waiting[pid], peer.addr, peer.port)
	w.waiting[pid] = append(peers, peer)
}

func (w *sshWatch) dropWaiting(pid int, addr netip.Addr, port uint16) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.waiting[pid] = dropPeer(w.waiting[pid], addr, port)
	if len(w.waiting[pid]) == 0 {
		delete(w.waiting, pid)
	}
}

func (w *sshWatch) rememberPublished(pid int, key sessionKey) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, existing := range w.published[pid] {
		if existing == key {
			return
		}
	}
	w.published[pid] = append(w.published[pid], key)
}

func (w *sshWatch) clearWaiting(pid int) {
	w.mu.Lock()
	delete(w.waiting, pid)
	w.mu.Unlock()
}

func dropPeer(peers []sshPeer, addr netip.Addr, port uint16) []sshPeer {
	out := peers[:0]
	for _, peer := range peers {
		if peer.addr == addr && peer.port == port {
			continue
		}
		out = append(out, peer)
	}
	return out
}

func dropKey(keys []sessionKey, addr netip.Addr, port uint16) []sessionKey {
	out := keys[:0]
	for _, key := range keys {
		if key.addr == addr && key.port == port {
			continue
		}
		out = append(out, key)
	}
	return out
}

func (w *sshWatch) deleteConn(pid int) error {
	if w.conns == nil {
		return nil
	}
	err := w.conns.Delete(uint32(pid))
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (w *sshWatch) Close() error {
	if w == nil {
		return nil
	}
	var errs []error
	if w.reader != nil {
		errs = append(errs, w.reader.Close())
		w.reader = nil
	}
	for _, lnk := range w.links {
		errs = append(errs, lnk.Close())
	}
	w.links = nil
	for _, prog := range w.progs {
		errs = append(errs, prog.Close())
	}
	w.progs = nil
	for _, m := range []*ebpf.Map{w.events, w.acceptPtrs, w.pend, w.conns} {
		if m != nil {
			errs = append(errs, m.Close())
		}
	}
	w.events, w.acceptPtrs, w.pend, w.conns = nil, nil, nil, nil
	return errors.Join(errs...)
}

func fieldAt(format, field string, size int) (int, error) {
	offset, got, err := fieldOffset(format, field)
	if err != nil {
		return 0, fmt.Errorf("attach SSH session tracepoint: %w", err)
	}
	if offset < 0 || got != size || offset+got > 4096 {
		return 0, fmt.Errorf("attach SSH session tracepoint: %s offset %d size %d", field, offset, got)
	}
	return offset, nil
}
