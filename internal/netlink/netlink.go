// Package netlink has the few rtnetlink and nfnetlink calls dfw needs,
// written against the syscall package.
package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
)

var ne = binary.NativeEndian

const (
	rtmNewNsid = 88
	rtmGetNsid = 90

	iflaAddress     = 1
	iflaIfname      = 3
	iflaLink        = 5
	iflaMaster      = 10
	iflaLinkinfo    = 18
	iflaInfoKind    = 1
	iflaLinkNetnsid = 37
	iflaTargetNsid  = 46

	netnsaNsid = 1
	netnsaPid  = 2

	nfnlSubsysNftables = 10
	nfnlgrpNftables    = 7
	nfprotoBridge      = 7
	nftMsgNewgen       = 16

	rtnlgrpLink       = 1
	rtnlgrpIPv4Ifaddr = 5
	rtnlgrpIPv6Ifaddr = 9
	rtScopeLink       = 253
	rtScopeHost       = 254

	solNetlink   = 270 // not in package syscall
	nlmFDumpIntr = 0x10
)

// errDumpIntr means the kernel's answer may be inconsistent because things
// changed during a dump; asking again fixes it.
var errDumpIntr = errors.New("netlink dump interrupted")

// Link is a network interface.
type Link struct {
	Index     int
	Name      string
	Kind      string // "veth", "bridge", ...
	MAC       net.HardwareAddr
	Master    int // index of the bridge it is attached to, or 0
	Peer      int // IFLA_LINK: for a veth, the peer's index in its namespace
	PeerNetns int // IFLA_LINK_NETNSID, or -1 when the peer is local
}

type attr struct {
	typ  uint16
	data []byte
}

func appendAttr(b []byte, typ uint16, data []byte) []byte {
	l := 4 + len(data)
	b = ne.AppendUint16(b, uint16(l))
	b = ne.AppendUint16(b, typ)
	b = append(b, data...)
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func parseAttrs(b []byte) []attr {
	var out []attr
	for len(b) >= 4 {
		l := int(ne.Uint16(b))
		if l < 4 || l > len(b) {
			break
		}
		out = append(out, attr{ne.Uint16(b[2:]) & 0x3fff, b[4:l]})
		b = b[min((l+3)&^3, len(b)):]
	}
	return out
}

func i32(v int32) []byte { return ne.AppendUint32(nil, uint32(v)) }

// request sends one rtnetlink request and returns the payloads of the replies.
func request(typ, flags uint16, body []byte) ([][]byte, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, os.NewSyscallError("socket", err)
	}
	defer syscall.Close(fd)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, os.NewSyscallError("bind", err)
	}
	msg := ne.AppendUint32(nil, uint32(16+len(body)))
	msg = ne.AppendUint16(msg, typ)
	msg = ne.AppendUint16(msg, flags|syscall.NLM_F_REQUEST)
	msg = ne.AppendUint32(msg, 1)
	msg = ne.AppendUint32(msg, 0)
	msg = append(msg, body...)
	if err := syscall.Sendto(fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return nil, os.NewSyscallError("sendto", err)
	}
	var out [][]byte
	intr := false
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			return nil, os.NewSyscallError("recvfrom", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, err
		}
		for _, m := range msgs {
			if m.Header.Flags&nlmFDumpIntr != 0 {
				intr = true
			}
			switch m.Header.Type {
			case syscall.NLMSG_DONE:
				if intr {
					return nil, errDumpIntr
				}
				return out, nil
			case syscall.NLMSG_ERROR:
				if len(m.Data) < 4 {
					return nil, errors.New("netlink: short error")
				}
				if e := -int32(ne.Uint32(m.Data)); e != 0 {
					return nil, syscall.Errno(e)
				}
				return out, nil // ACK
			}
			// m.Data points into buf, which the next read overwrites.
			out = append(out, append([]byte(nil), m.Data...))
			if m.Header.Flags&syscall.NLM_F_MULTI == 0 {
				return out, nil
			}
		}
	}
}

// Links lists interfaces. With nsid >= 0 it lists the namespace that the
// host knows by that ID instead of the host's own.
func Links(nsid int) ([]Link, error) {
	body := make([]byte, syscall.SizeofIfInfomsg)
	if nsid >= 0 {
		body = appendAttr(body, iflaTargetNsid, i32(int32(nsid)))
	}
	msgs, err := request(syscall.RTM_GETLINK, syscall.NLM_F_DUMP, body)
	for try := 0; errors.Is(err, errDumpIntr) && try < 5; try++ {
		msgs, err = request(syscall.RTM_GETLINK, syscall.NLM_F_DUMP, body)
	}
	if err != nil {
		return nil, fmt.Errorf("list links: %w", err)
	}
	var links []Link
	for _, m := range msgs {
		if l, ok := parseLink(m); ok {
			links = append(links, l)
		}
	}
	return links, nil
}

func parseLink(m []byte) (Link, bool) {
	if len(m) < syscall.SizeofIfInfomsg {
		return Link{}, false
	}
	l := Link{Index: int(int32(ne.Uint32(m[4:]))), PeerNetns: -1}
	for _, a := range parseAttrs(m[syscall.SizeofIfInfomsg:]) {
		switch a.typ {
		case iflaIfname:
			l.Name = cstr(a.data)
		case iflaAddress:
			l.MAC = net.HardwareAddr(append([]byte(nil), a.data...))
		case iflaMaster:
			l.Master = int(ne.Uint32(a.data))
		case iflaLink:
			l.Peer = int(ne.Uint32(a.data))
		case iflaLinkNetnsid:
			l.PeerNetns = int(int32(ne.Uint32(a.data)))
		case iflaLinkinfo:
			for _, b := range parseAttrs(a.data) {
				if b.typ == iflaInfoKind {
					l.Kind = cstr(b.data)
				}
			}
		}
	}
	return l, true
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// NsidOfPid returns the ID under which the host knows the network namespace
// of process pid, assigning one if needed. Needs only CAP_NET_ADMIN.
func NsidOfPid(pid int) (int, error) {
	get := func() (int, error) {
		body := appendAttr(make([]byte, 4), netnsaPid, ne.AppendUint32(nil, uint32(pid)))
		msgs, err := request(rtmGetNsid, 0, body)
		if err != nil {
			return -1, err
		}
		for _, m := range msgs {
			for _, a := range parseAttrs(m[min(4, len(m)):]) {
				if a.typ == netnsaNsid && len(a.data) >= 4 {
					return int(int32(ne.Uint32(a.data))), nil
				}
			}
		}
		return -1, errors.New("no nsid in reply")
	}
	id, err := get()
	if err == nil && id < 0 {
		body := appendAttr(make([]byte, 4), netnsaPid, ne.AppendUint32(nil, uint32(pid)))
		body = appendAttr(body, netnsaNsid, i32(-1))
		if _, err = request(rtmNewNsid, syscall.NLM_F_ACK, body); err == nil {
			id, err = get()
		}
	}
	if err == nil && id < 0 {
		err = errors.New("namespace has no ID")
	}
	if err != nil {
		return -1, fmt.Errorf("netns id of pid %d: %w", pid, err)
	}
	return id, nil
}

// WatchNftables calls changed whenever a bridge-family table named table
// changes, and when notifications were lost. It blocks; it returns only if
// the socket fails.
func WatchNftables(table string, changed func()) error {
	return watch(syscall.NETLINK_NETFILTER, []int{nfnlgrpNftables}, changed, func(m syscall.NetlinkMessage) bool {
		t := m.Header.Type
		if t>>8 != nfnlSubsysNftables || t&0xff == nftMsgNewgen || len(m.Data) < 4 || m.Data[0] != nfprotoBridge {
			return false
		}
		for _, a := range parseAttrs(m.Data[4:]) {
			if a.typ == 1 && cstr(a.data) == table {
				return true
			}
		}
		return false
	})
}

// WatchBridges calls changed whenever a bridge appears or disappears, and
// when notifications were lost. It blocks; it returns only if the socket
// fails.
func WatchBridges(changed func()) error {
	seen := map[int]bool{}
	if links, err := Links(-1); err == nil {
		for _, l := range links {
			if l.Kind == "bridge" {
				seen[l.Index] = true
			}
		}
	}
	return watch(syscall.NETLINK_ROUTE, []int{rtnlgrpLink}, changed, func(m syscall.NetlinkMessage) bool {
		t := m.Header.Type
		if t != syscall.RTM_NEWLINK && t != syscall.RTM_DELLINK {
			return false
		}
		l, ok := parseLink(m.Data)
		if !ok || l.Kind != "bridge" {
			return false
		}
		if t == syscall.RTM_DELLINK {
			delete(seen, l.Index)
			return true
		}
		if seen[l.Index] {
			return false
		}
		seen[l.Index] = true
		return true
	})
}

// WatchAddrs calls changed whenever a host address is added or removed,
// leaving out loopback and link-local ones (every new veth gets one), and
// when notifications were lost. It blocks; it returns only if the socket
// fails.
func WatchAddrs(changed func()) error {
	return watch(syscall.NETLINK_ROUTE, []int{rtnlgrpIPv4Ifaddr, rtnlgrpIPv6Ifaddr}, changed, func(m syscall.NetlinkMessage) bool {
		t := m.Header.Type
		// struct ifaddrmsg: family, prefixlen, flags, scope, index.
		return (t == syscall.RTM_NEWADDR || t == syscall.RTM_DELADDR) && len(m.Data) >= 4 &&
			m.Data[3] != rtScopeLink && m.Data[3] != rtScopeHost
	})
}

// watch joins netlink multicast groups and calls changed for every message
// that match accepts, and when messages were lost.
func watch(proto int, groups []int, changed func(), match func(syscall.NetlinkMessage) bool) error {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, proto)
	if err != nil {
		return os.NewSyscallError("socket", err)
	}
	defer syscall.Close(fd)
	_ = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUFFORCE, 4<<20)
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return os.NewSyscallError("bind", err)
	}
	for _, g := range groups {
		if err := syscall.SetsockoptInt(fd, solNetlink, syscall.NETLINK_ADD_MEMBERSHIP, g); err != nil {
			return os.NewSyscallError("join netlink group", err)
		}
	}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err == syscall.ENOBUFS {
			changed() // lost notifications: assume the worst
			continue
		}
		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return os.NewSyscallError("recvfrom", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			changed()
			continue
		}
		for _, m := range msgs {
			if match(m) {
				changed()
				break
			}
		}
	}
}
