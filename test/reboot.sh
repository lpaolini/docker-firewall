#!/bin/bash
# Reboot scenarios. Root on a DISPOSABLE Debian 13 machine with Docker, the
# dfw-tools image and the dfw package installed.
#
#   ./reboot.sh prepare [socket]   [dfw enable]   reboot   ./reboot.sh verify
#
# prepare writes /etc/dfw/rules for a network rbnet, and starts containers
# with restart=always that send UDP from their first instruction: two on
# rbnet (rb-out, allowed out to $EXT, and rb-none, no rules) and one on the
# default bridge (rb-free, which dfw must leave alone). It installs a capture
# unit that starts before Docker. With "socket", Docker is socket-activated
# instead of started at boot, and verify starts it through docker.socket.
#
# If dfw is enabled, verify checks that nothing escaped from rbnet before or
# after the rules came in, and that rb-free was never blocked. If dfw is only
# installed, it checks that the reboot changed no traffic.
set -uo pipefail
IMG=${IMG:-dfw-tools}
EXT=${EXT:-1.1.1.1}
EXT2=${EXT2:-1.0.0.1}
PCAP=/var/tmp/dfw-reboot.pcap

case "${1:-}" in
prepare)
	docker rm -f rb-none rb-out rb-free >/dev/null 2>&1
	docker network inspect rbnet >/dev/null 2>&1 || docker network create --subnet 10.212.0.0/24 rbnet >/dev/null
	rm -f $PCAP
	printf 'network rbnet\nallow [rb-out] -> %s\n' "$EXT" >/etc/dfw/rules
	SEND="while :; do echo x | socat - UDP-DATAGRAM:255.255.255.255:PORT,broadcast; echo x | socat - UDP:$EXT2:PORT; echo x | socat - UDP:\$(ip route | awk '/default/ {print \$3}'):PORT; sleep 0.05; done"
	docker run -d --restart always --name rb-none --network rbnet "$IMG" sh -c "${SEND//PORT/9997}" >/dev/null
	docker run -d --restart always --name rb-out --network rbnet "$IMG" sh -c "${SEND//PORT/9997} & sleep infinity" >/dev/null
	docker run -d --restart always --name rb-free "$IMG" sh -c "${SEND//PORT/9996}" >/dev/null
	cat >/etc/systemd/system/dfw-capture.service <<EOF
[Unit]
Description=capture container UDP from boot, for reboot.sh
DefaultDependencies=no
After=local-fs.target
Before=docker.service docker.socket

[Service]
ExecStart=/usr/bin/tcpdump -Z root -i any -n -U -w $PCAP udp port 9997 or udp port 9996

[Install]
WantedBy=sysinit.target
EOF
	systemctl daemon-reload
	systemctl enable dfw-capture.service >/dev/null 2>&1
	if [ "${2:-}" = socket ]; then
		systemctl disable docker.service >/dev/null 2>&1
		systemctl enable docker.socket >/dev/null 2>&1
		echo "Docker will be socket-activated"
	else
		systemctl enable docker.service docker.socket >/dev/null 2>&1
	fi
	systemctl is-active -q dfw && dfw apply
	echo "prepared; run dfw enable if you want it, reboot, then run: $0 verify"
	;;
verify)
	FAILED=0
	if ! systemctl is-active -q docker; then
		echo "starting Docker through docker.socket"
		docker version >/dev/null
	fi
	for _ in $(seq 120); do
		[ "$(docker inspect -f '{{.State.Running}}' rb-out 2>/dev/null)" = true ] && break
		sleep 1
	done
	sleep 10
	if ! systemctl is-active -q dfw-capture.service; then
		echo "FAIL: the capture did not run this boot"; journalctl -b -u dfw-capture --no-pager | tail -3; exit 1
	fi
	systemctl stop dfw-capture.service
	# Packets seen leaving a container's veth toward the bridge are fine; any
	# copy seen elsewhere got past the bridge.
	tcpdump -r $PCAP -n 2>/dev/null >/var/tmp/dfw-reboot.all
	grep '\.9997: ' /var/tmp/dfw-reboot.all >/var/tmp/dfw-reboot.txt
	total=$(wc -l </var/tmp/dfw-reboot.txt)
	escaped=$(grep -Evc ' veth[0-9a-f]+ (In|B|P|M) ' /var/tmp/dfw-reboot.txt)
	free=$(grep '\.9996: ' /var/tmp/dfw-reboot.all | grep -Evc ' veth[0-9a-f]+ (In|B|P|M) ')
	echo "rbnet: captured $total packets, $escaped beyond the veths; rb-free: $free beyond its veth"
	if dfw active 2>/dev/null; then
		echo "dfw is enabled: nothing may escape from rbnet, and rb-free must flow"
		[ "$escaped" = 0 ] && echo "PASS: no packet escaped from boot on" || { echo "FAIL: packets escaped:"; grep -Ev ' veth[0-9a-f]+ (In|B|P|M) ' /var/tmp/dfw-reboot.txt | head; FAILED=1; }
		[ "$total" -gt 0 ] && echo "PASS: the containers did send (capture works)" || { echo "FAIL: nothing captured at all"; FAILED=1; }
		docker exec rb-out ping -c1 -W3 "$EXT" >/dev/null && echo "PASS: rb-out got its rules" || { echo "FAIL: rb-out has no access"; FAILED=1; }
		docker exec rb-none ping -c1 -W3 "$EXT" >/dev/null && { echo "FAIL: rb-none has access"; FAILED=1; } || echo "PASS: rb-none blocked"
		[ "$free" -gt 0 ] && echo "PASS: rb-free, on another network, flowed" || { echo "FAIL: rb-free was blocked"; FAILED=1; }
		docker exec rb-free ping -c1 -W3 "$EXT" >/dev/null && echo "PASS: rb-free has access" || { echo "FAIL: rb-free has no access"; FAILED=1; }
	else
		echo "dfw is not enabled: the reboot must change nothing"
		nft list table bridge fw >/dev/null 2>&1 && { echo "FAIL: table exists"; FAILED=1; } || echo "PASS: no table"
		[ "$escaped" -gt 0 ] && echo "PASS: traffic flows as before" || { echo "FAIL: no traffic"; FAILED=1; }
	fi
	systemctl disable dfw-capture.service >/dev/null 2>&1
	rm -f /etc/systemd/system/dfw-capture.service $PCAP
	systemctl enable docker.service >/dev/null 2>&1
	docker rm -f rb-none rb-out rb-free >/dev/null
	exit $FAILED
	;;
*)
	echo "usage: $0 prepare [socket] | verify" >&2
	exit 2
	;;
esac
