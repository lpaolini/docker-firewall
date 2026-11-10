package netlink

import (
	"syscall"
	"testing"
)

func TestAddrChanges(t *testing.T) {
	msg := func(typ uint16, scope byte, addr ...byte) syscall.NetlinkMessage {
		data := ne.AppendUint32([]byte{syscall.AF_INET, 24, 0, scope}, 2) // ifaddrmsg, index 2
		data = appendAttr(data, syscall.IFA_ADDRESS, addr)
		return syscall.NetlinkMessage{Header: syscall.NlMsghdr{Type: typ}, Data: data}
	}
	match := addrChanges()
	for i, tc := range []struct {
		m    syscall.NetlinkMessage
		want bool
	}{
		{msg(syscall.RTM_NEWADDR, 0, 10, 0, 0, 1), true},
		{msg(syscall.RTM_NEWADDR, 0, 10, 0, 0, 1), false}, // lifetimes refreshed
		{msg(syscall.RTM_NEWADDR, 0, 10, 0, 0, 2), true},
		{msg(syscall.RTM_DELADDR, 0, 10, 0, 0, 1), true},
		{msg(syscall.RTM_NEWADDR, 0, 10, 0, 0, 1), true}, // back again
		{msg(syscall.RTM_NEWADDR, syscall.RT_SCOPE_LINK, 169, 254, 0, 1), false},
		{msg(syscall.RTM_NEWADDR, syscall.RT_SCOPE_HOST, 127, 0, 0, 1), false},
		{msg(syscall.RTM_NEWLINK, 0, 10, 0, 0, 3), false},
	} {
		if got := match(tc.m); got != tc.want {
			t.Errorf("message %d: match = %v, want %v", i, got, tc.want)
		}
	}
}
