#!/bin/bash
# Gate test, design section 8. Needs only Docker, nft, tcpdump and socat.
#
# Run as root on a DISPOSABLE Debian 13 VM: it loads nf_conntrack_bridge and
# installs a bridge table that blocks every container on the host.
#
#   PRIO=100 ./gate.sh            # chain priority to test (try -150 and 100)
#   N=1000 ./gate.sh first        # only question 3, N container starts
#
# The test image (dfw-tools) must exist before the table goes in, because the
# table blocks image builds:  FROM alpine  RUN apk add socat curl bind-tools
set -uo pipefail

PRIO=${PRIO:-100}
IMG=${IMG:-dfw-tools}
EXT=${EXT:-1.1.1.1}
N=${N:-1000}
NET=gate
FAILED=0

say()  { printf '\n== %s\n' "$*"; }
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; FAILED=1; }

cleanup() {
	# Stop captures, then remove every container, before the table goes.
	pkill -f "tcpdump .*/tmp/gate-q3" 2>/dev/null
	docker ps -q --filter "network=$NET" | xargs -r docker rm -f >/dev/null 2>&1
	docker rm -f g-srv g-cli g-peer >/dev/null 2>&1
	docker network rm $NET >/dev/null 2>&1
	nft delete table bridge gate 2>/dev/null
	true
}

base_table() {
	nft -f - <<EOF
add table bridge gate
delete table bridge gate
table bridge gate {
	map out_by_port { type iface_index : verdict; }
	map in_by_port { type iface_index : verdict; }
	chain from_container {
		type filter hook prerouting priority $PRIO; policy accept;
		iif vmap @out_by_port
		iifname "veth*" counter drop
	}
	chain to_container {
		type filter hook postrouting priority $PRIO; policy accept;
		oif vmap @in_by_port
		oifname "veth*" counter drop
	}
}
EOF
}

veth() { nsenter -t "$(docker inspect -f '{{.State.Pid}}' "$1")" -n ip -o link show eth0 | sed -n 's/.*@if\([0-9]*\).*/\1/p'; }
ip4() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").IPAddress}}" "$1"; }
ip6() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").GlobalIPv6Address}}" "$1"; }

# rules NAME OUT_RULES IN_RULES: per-container chains, shaped like section 4.2.
rules() {
	local n=$1 idx
	idx=$(veth "$n")
	nft -f - <<EOF
add chain bridge gate ${n}_out
add chain bridge gate ${n}_in
flush chain bridge gate ${n}_out
flush chain bridge gate ${n}_in
add rule bridge gate ${n}_out ether type arp accept
add rule bridge gate ${n}_out icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
add rule bridge gate ${n}_out ct state established,related counter accept
add rule bridge gate ${n}_out ct state invalid counter drop
add rule bridge gate ${n}_out ct state new log prefix "gate ${n} out new: " level info
$(printf '%s\n' "$2" | sed "/^$/d; s/^/add rule bridge gate ${n}_out /")
add rule bridge gate ${n}_out counter drop
add rule bridge gate ${n}_in ether type arp accept
add rule bridge gate ${n}_in icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert } accept
add rule bridge gate ${n}_in ct state established,related counter accept
add rule bridge gate ${n}_in ct state invalid counter drop
add rule bridge gate ${n}_in ct state new log prefix "gate ${n} in new: " level info
$(printf '%s\n' "$3" | sed "/^$/d; s/^/add rule bridge gate ${n}_in /")
add rule bridge gate ${n}_in counter drop
add element bridge gate out_by_port { $idx : jump ${n}_out }
add element bridge gate in_by_port { $idx : jump ${n}_in }
EOF
}

# can FROM HOST PORT [proto]: does a connection get an answer?
can() {
	local proto=${4:-TCP}
	[ "$(docker exec "$1" socat -T2 - "$proto:$2:$3,connect-timeout=2" </dev/null 2>/dev/null)" = hi ]
}

setup() {
	cleanup
	docker network create --ipv6 --subnet 10.201.250.0/24 --subnet fd00:250::/64 $NET >/dev/null || exit 1
	for c in g-srv g-cli g-peer; do
		# Distinct host ports: Docker 29 reuses one ephemeral port per binding.
		local pub=""
		[ $c = g-srv ] && pub="-p 127.0.0.1:$((${PUB:-18080} + 1)):8080 -p ${PUB:-18080}:8080"
		docker run -d --name $c --network $NET $pub "$IMG" sh -c \
			'socat TCP6-LISTEN:8080,fork,ipv6only=0 SYSTEM:"echo hi" & socat UDP6-RECVFROM:8080,fork,ipv6only=0 SYSTEM:"echo hi" & sleep infinity' >/dev/null
	done
	base_table
}

q1() {
	say "Q1/Q2 at priority $PRIO: ct state, direct traffic, published ports"
	local S4 S6 C4 C6 P4
	S4=$(ip4 g-srv) S6=$(ip6 g-srv) C4=$(ip4 g-cli) C6=$(ip6 g-cli) P4=$(ip4 g-peer)
	can g-cli "$S4" 8080 && fail "blocked before rules" || pass "g-cli -> g-srv blocked by base table alone"

	rules g-cli "ip daddr $S4 tcp dport 8080 ct state new accept
ip6 daddr $S6 tcp dport 8080 ct state new accept
ip daddr $S4 udp dport 8080 ct state new accept
ip daddr $EXT ct state new accept" ""
	rules g-srv "" "ip saddr $C4 tcp dport 8080 ct state new accept
ip6 saddr $C6 tcp dport 8080 ct state new accept
ip saddr $C4 udp dport 8080 ct state new accept
ct state new accept"
	rules g-peer "" ""

	can g-cli "$S4" 8080 && pass "TCP v4 allowed, reply passed" || fail "TCP v4 allowed connection failed"
	can g-cli "[$S6]" 8080 && pass "TCP v6 allowed, reply passed" || fail "TCP v6 allowed connection failed"
	can g-cli "$S4" 8080 UDP && pass "UDP v4 allowed, reply passed" || fail "UDP v4 allowed flow failed"
	can g-srv "$C4" 8080 && fail "unsolicited g-srv -> g-cli passed" || pass "unsolicited inbound to g-cli dropped"
	can g-srv "[$C6]" 8080 && fail "unsolicited v6 g-srv -> g-cli passed" || pass "unsolicited v6 inbound dropped"
	can g-cli "$P4" 8080 && fail "g-cli -> g-peer passed with no rules" || pass "g-cli -> g-peer (no rule) dropped"
	docker exec g-cli ping -c1 -W3 "$EXT" >/dev/null && pass "g-cli -> $EXT (address-only rule, ICMP) passed" || fail "ping $EXT failed"
	docker exec g-cli curl -s -m5 -o /dev/null "http://$EXT/" && pass "g-cli -> $EXT TCP through NAT passed" || fail "curl $EXT failed"
	local est
	est=$(nft -j list chain bridge gate g-cli_in | jq '[.nftables[].rule? | select(.) | select(.expr[0].match.right == ["established","related"]) | .expr[1].counter.packets] | add')
	[ "${est:-0}" -gt 0 ] && pass "replies matched ct established in g-cli_in ($est packets)" || fail "no ct established matches"

	say "Q2/Q5: source addresses seen by g-srv_in for published port 8080"
	local pub_lo pub_any gw
	gw=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").Gateway}}" g-srv)
	pub_lo=$(docker port g-srv 8080/tcp | grep 127.0.0.1 | cut -d: -f2)
	pub_any=${PUB:-18080}
	dmesg -C
	socat -T2 - TCP:127.0.0.1:"$pub_lo" </dev/null >/dev/null 2>&1
	socat -T2 - TCP6:[::1]:"$pub_any" </dev/null >/dev/null 2>&1
	local hostip; hostip=$(ip -4 route get 1.1.1.1 | sed -n 's/.* src \([0-9.]*\).*/\1/p')
	socat -T2 - TCP:"$hostip":"$pub_any" </dev/null >/dev/null 2>&1
	docker exec g-cli socat -T2 - TCP:"$hostip":"$pub_any" </dev/null >/dev/null 2>&1
	socat -T2 - TCP6:[::1]:"${PUB:-18080}" </dev/null >/dev/null 2>&1
	if [ -n "${EXT_WAIT:-}" ]; then echo "waiting ${EXT_WAIT}s for an external client on port ${PUB:-18080}"; sleep "$EXT_WAIT"; fi
	sleep 1
	echo "gateway=$gw host=$hostip published lo=$pub_lo any=$pub_any"
	dmesg | grep -o 'gate [^:]*: .*' | sed -E 's/(MACSRC|MACDST|MACPROTO|LEN|TOS|PREC|TTL|ID|WINDOW|RES|URGP|TC|HOPLIMIT|FLOWLBL|SPT)=[^ ]* //g' | sort | uniq -c
}

q3() {
	say "Q3: first packet of a new container, $N starts, no rules for it"
	base_table
	rules g-peer "" "ct state new accept"
	# CONTROL=1 removes the table, to prove the captures see packets that do escape.
	[ "${CONTROL:-}" = 1 ] && nft delete table bridge gate
	local bmac gw bcast
	bmac=$(cat /sys/class/net/br-"$(docker network inspect -f '{{.Id}}' $NET | cut -c1-12)"/address)
	gw=$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").Gateway}}" g-srv)
	bcast=10.201.250.255
	local pv; pv=$(ip -o link | awk -F'[ :@]+' -v i="$(veth g-peer)" '$1==i {print $2}')
	local pvmac; pvmac=$(cat /sys/class/net/"$pv"/address)
	local br; br=br-$(docker network inspect -f '{{.Id}}' $NET | cut -c1-12)
	rm -f /tmp/gate-q3-*.pcap
	tcpdump -i "$br" -n -U -w /tmp/gate-q3-br.pcap "not ether src $bmac and not ether src $(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").MacAddress}}" g-peer)" 2>/dev/null &
	local t1=$!
	tcpdump -i "$pv" -n -U -w /tmp/gate-q3-peer.pcap "not ether src $bmac and not ether src $pvmac and not ether src $(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").MacAddress}}" g-peer)" 2>/dev/null &
	local t2=$!
	local wan; wan=$(ip -o route get "$EXT" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
	tcpdump -i "$wan" -n -U -w /tmp/gate-q3-wan.pcap "udp port 9999" 2>/dev/null &
	local t3=$!
	sleep 2
	local i
	for i in $(seq "$N"); do
		docker run --rm --network $NET "$IMG" sh -c \
			"echo x | socat - UDP-DATAGRAM:$bcast:9999,broadcast; echo x | socat - UDP:$gw:9999; echo x | socat - UDP:$(ip4 g-peer):9999; echo x | socat - UDP:$EXT:9999" \
			>/dev/null 2>&1
		[ $((i % 100)) = 0 ] && echo "  $i starts"
	done
	sleep 2
	kill $t1 $t2 $t3; wait $t1 $t2 $t3 2>/dev/null
	local nb np nw
	nb=$(tcpdump -r /tmp/gate-q3-br.pcap -n 2>/dev/null | wc -l)
	np=$(tcpdump -r /tmp/gate-q3-peer.pcap -n 2>/dev/null | wc -l)
	nw=$(tcpdump -r /tmp/gate-q3-wan.pcap -n 2>/dev/null | wc -l)
	echo "frames from containers: on bridge device $nb, on peer veth $np, udp/9999 on $wan $nw"
	[ "$nb$np$nw" = 000 ] && pass "no packets escaped in $N starts" || fail "packets escaped"
	nft list chain bridge gate from_container 2>/dev/null | grep counter
}

q6() {
	say "Q6: does Docker's DNS send external lookups through the container's veth?"
	base_table
	rules g-cli "" ""
	local v; v=$(ip -o link | awk -F'[ :@]+' -v i="$(veth g-cli)" '$1==i {print $2}')
	timeout 8 tcpdump -i "$v" -n -c 4 "port 53" 2>/dev/null > /tmp/gate-q6 &
	sleep 1
	docker exec g-cli nslookup -timeout=2 -retry=0 example.com >/dev/null 2>&1
	wait
	cat /tmp/gate-q6
	docker exec g-cli cat /etc/resolv.conf | grep -E 'nameserver|ExtServers'
	if grep -q '\.53: ' /tmp/gate-q6; then echo "ANSWER: yes, external lookups leave through the container's veth"; else echo "ANSWER: no"; fi
}

trap cleanup EXIT
setup
case "${1:-all}" in
	all) q1; q6; q3 ;;
	q1) q1 ;;
	first) q3 ;;
	dns) q6 ;;
esac
[ $FAILED = 0 ] && echo "GATE: all checks passed (priority $PRIO)" || echo "GATE: FAILURES (priority $PRIO)"
exit $FAILED
