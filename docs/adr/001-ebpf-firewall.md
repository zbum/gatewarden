# ADR 001: XDP firewall with cilium/ebpf

Date: 2026-09-29
Status: Accepted (dependency and ADR authorized by the user). Amended 2026-10-03: blocking is eBPF/XDP only.

Use github.com/cilium/ebpf to load an XDP program and manage an IP hash map
without shell commands or a build-time C compiler. Generate instructions with
its Go assembler. Block and unblock only through that map on an explicit
Ethernet interface.

The existing manager owns failure thresholds, allowlists and ban expiry. XDP
checks IPv4/IPv6 source addresses (including up to two VLAN headers) and drops
blocked traffic on the selected ingress interface, including established sessions.
This does not send TCP resets. Forwarded traffic on that interface is also affected;
other interfaces and encapsulated inner IP headers are not inspected.

Use generic XDP and an unpinned BPF link: existing programs are not replaced and
closing the process releases the link and maps. Require Linux with XDP BPF-link
support (upstream 5.9+) and sufficient BPF/network privileges. Attachment
failure stops startup.

SSH failure detection stays in userspace. Gatewarden reads OpenSSH
authentication logs, counts failures, and then updates the XDP map.

Validation: portable lifecycle/map tests and Linux kernel program tests for packet
parsing and decisions. Kernel tests explicitly opt in and require a privileged
Linux environment. Cross-compile Linux, macOS and Windows; enforcement is Linux-only.

Reference: https://github.com/cilium/ebpf/tree/v0.20.0
