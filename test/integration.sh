#!/bin/bash
# Acceptance tests for dfw. Run as root on a
# DISPOSABLE Debian 13 machine with Docker and docker compose, with the dfw
# package NOT installed, and socat, curl, tcpdump and jq on the host:
#
#   ./integration.sh dfw_0.1.0_amd64.deb
#
# It installs, enables, upgrades, disables and removes the package, rewrites
# /etc/dfw/rules (applying it with dfw apply), and runs `nft flush ruleset`. The image dfw-tools must exist:
#   FROM alpine
#   RUN apk add --no-cache socat curl bind-tools tcpdump iproute2
#
# Reboot scenarios need a reboot in the middle; see reboot.sh.
set -uo pipefail

DEB=${1:?usage: integration.sh path/to/dfw.deb}
IMG=${IMG:-dfw-tools}
EXT=${EXT:-1.1.1.1}  # an internet address that answers ping and HTTP
EXT2=${EXT2:-1.0.0.1} # another one
P=acc
NET=${P}_default # a filtered network
TWO=${P}_two     # another filtered network
FREE=${P}_free   # a network dfw must leave alone
RULES=/etc/dfw/rules
RULESD=/etc/dfw/rules.d
FAILED=0

# Preflight: refuse to start rather than fail checks for reasons outside dfw.
need=()
for t in socat curl tcpdump jq nsenter journalctl docker; do command -v $t >/dev/null || need+=($t); done
docker compose version >/dev/null 2>&1 || need+=("docker compose")
[ ${#need[@]} = 0 ] || { echo "missing on the host: ${need[*]} (apt-get install socat curl tcpdump jq)"; exit 2; }
[ "$(id -u)" = 0 ] || { echo "run as root"; exit 2; }
dpkg-query -W -f='${Status}' dfw 2>/dev/null | grep -q "ok installed" &&
	{ echo "dfw is installed: run dfw disable and apt-get purge dfw first"; exit 2; }
docker image inspect "$IMG" >/dev/null 2>&1 || { echo "image $IMG is missing (see the header)"; exit 2; }
DIR=$(mktemp -d)

say() { printf '\n== %s\n' "$*"; }
ok() { echo "PASS: $*"; }
bad() { echo "FAIL: $*"; FAILED=1; }
yes_() { local d=$1; shift; if "$@"; then ok "$d"; else bad "$d"; fi; }
no_() { local d=$1; shift; if "$@"; then bad "not blocked: $d"; else ok "blocked: $d"; fi; }
logged() { # logged PATTERN: wait for dfw to log it
	for _ in $(seq 50); do journalctl -u dfw --since "$START" | grep "$1" >/dev/null && return 0; sleep 0.2; done
	return 1
}
eventually() { # eventually CMD...: retry for up to 10 s
	for _ in $(seq 20); do "$@" && return 0; sleep 0.5; done
	return 1
}
save_rules() { # save_rules FILE: stdin to FILE atomically, without applying it
	mkdir -p "$(dirname "$1")"
	cat >"$1.tmp" && mv "$1.tmp" "$1"
}
apply() { # apply: dfw apply, if dfw is running
	systemctl is-active -q dfw || return 0
	dfw apply >"$DIR/apply" 2>&1 || { echo "  (dfw apply failed:)"; tail -3 "$DIR/apply"; }
}
write_rules() { save_rules "$1" && apply; }  # write_rules FILE: save stdin and apply it
drop_rules() { rm -f "$1"; apply; }

# Every test container answers "hi" on TCP and UDP ports 80, 5432 and 9999.
SERVE='for p in 80 5432 9999; do socat TCP6-LISTEN:$p,fork,ipv6only=0,reuseaddr SYSTEM:"echo hi; cat" & socat UDP6-RECVFROM:$p,fork,ipv6only=0 SYSTEM:"echo hi" & done; exec sleep infinity'

tcp() { [ "$(docker exec "$1" socat -T3 - "TCP:$2:$3,connect-timeout=3" </dev/null 2>/dev/null)" = hi ]; }
udp() { case "$(docker exec "$1" sh -c "echo x | socat -T8 - UDP:$2:$3" 2>/dev/null)" in hi*) ;; *) return 1 ;; esac; }
pings() { docker exec "$1" ping -c1 -W3 "$2" >/dev/null 2>&1; }
web() { docker exec "$1" curl -s -m5 -o /dev/null "http://$2/"; }
ipon() { docker inspect -f "{{(index .NetworkSettings.Networks \"$2\").IPAddress}}" "$1"; }
ip4() { ipon "$1" $NET; }
ip6() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").GlobalIPv6Address}}" "$1"; }
gw() { docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").Gateway}}" "$1"; }
installed() { dpkg-query -W -f='${Status}' dfw 2>/dev/null | grep "ok installed" >/dev/null; }
key() { echo "c$(docker inspect -f '{{.Id}}' "$1" | cut -c1-16)"; }
has_rules() { nft list chain bridge fw "$(key "$1")_out" >/dev/null 2>&1; }
wait_rules() {
	for _ in $(seq 100); do has_rules "$1" && return 0; sleep 0.1; done
	return 1
}
serve() { # serve NAME [docker run args...]
	local n=$1; shift
	docker run -d --name "$n" --network $NET "$@" "$IMG" sh -c "$SERVE" >/dev/null
}

cleanup() {
	docker compose -p $P -f "$DIR/compose.yaml" down -t 0 >/dev/null 2>&1
	docker rm -f ic1 ic2 internet pub pubok kk sp squat ct-cli ct-srv ct-new lat dn1 dn2 dn3 nw1 >/dev/null 2>&1
	docker network rm $NET $TWO $FREE acc_new >/dev/null 2>&1
	rm -rf "$DIR" "$RULESD"
}
trap cleanup EXIT

START=$(date '+%Y-%m-%d %H:%M:%S')
cat >"$DIR/compose.yaml" <<EOF
name: $P
x-srv: &srv
  image: $IMG
  command: ["sh", "-c", '${SERVE//\$/\$\$}']
networks:
  default:
    enable_ipv6: true
    ipam:
      config:
        - subnet: 10.210.0.0/24
        - subnet: fd00:210::/64
  free:
    ipam:
      config:
        - subnet: 10.211.0.0/24
  two:
    ipam:
      config:
        - subnet: 10.213.0.0/24
services:
  a: *srv
  b: *srv
  lanhost: *srv
  d: *srv
  n: *srv
  f:
    <<: *srv
    networks: [free]
  mh:
    <<: *srv
    networks: [default, free]
  t:
    <<: *srv
    networks: [two]
  t2:
    <<: *srv
    networks: [two]
  m2:
    <<: *srv
    networks: [default, two]
EOF

MAIN="network $NET
network $TWO
allow [t] -> $EXT
allow [m2] -> [b]:5432, [t]:80
allow [a] -> [b]:5432
allow [a] -> $EXT
allow [b] -> internet
allow lan -> [lanhost]
allow [d] -> rfc1918
allow [mh] -> internet"

say "installing the package changes no traffic"
installed && { echo "dfw is already installed; remove it first"; exit 1; }
docker compose -p $P -f "$DIR/compose.yaml" up -d >/dev/null 2>&1 || exit 1
A=acc-a-1 B=acc-b-1 L=acc-lanhost-1 D=acc-d-1 N=acc-n-1 F=acc-f-1 MH=acc-mh-1 T=acc-t-1 T2=acc-t2-1 M2=acc-m2-1
web $N "$EXT" || { echo "the container has no internet before dfw; fix the test host"; exit 1; }
dpkg --purge dfw >/dev/null 2>&1 # drop the rules a removed package left behind
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$DEB" >/dev/null 2>&1 || dpkg -i "$DEB" >/dev/null
yes_ "package installed" installed
yes_ "the package ships a rules file with no rules" sh -c "test -f $RULES && ! grep -v '^#' $RULES | grep -q ."
no_ "no table after install" nft list table bridge fw
yes_ "dfw.service neither enabled nor started" sh -c '! systemctl is-enabled -q dfw && ! systemctl is-active -q dfw'
yes_ "containers still reach the internet" web $N "$EXT"

say "plan and enable"
no_ "dfw enable with the shipped rules (no network)" sh -c "dfw enable >$DIR/enable 2>&1"
printf '%s\nallow [a] -> [b]:5432, oops:\n' "$MAIN" | write_rules $RULES
no_ "dfw enable with an error in the rules" sh -c "dfw enable >$DIR/enable 2>&1"
yes_ "the refusal names the line" grep -q "$RULES:11: destination" "$DIR/enable"
no_ "nothing changed by the refused enables" sh -c "nft list table bridge fw >/dev/null 2>&1"
echo "$MAIN" | write_rules $RULES
printf 'network %s\nallow [a] -> [nobody]\n' "$NET" >"$DIR/candidate"
dfw plan "$DIR/candidate" >"$DIR/plan" 2>&1
yes_ "plan FILE checks a candidate file" grep -qF "[nobody] matches no running container" "$DIR/plan"
dfw plan >"$DIR/plan" 2>&1
yes_ "plan lists the containers on the network, and only those" sh -c "grep -q '^acc-a-1' $DIR/plan && grep -q '^acc-n-1' $DIR/plan && ! grep -q '^acc-f-1' $DIR/plan"
yes_ "plan flags the unmentioned container" grep -q "no rule mentions it" "$DIR/plan"
yes_ "plan flags the container on two networks" grep -q "is also on network $FREE" "$DIR/plan"
yes_ "dfw enable" dfw enable
yes_ "dfw.service active" systemctl is-active -q dfw
yes_ "drop-in installed" test -f /etc/systemd/system/docker.service.d/dfw.conf
no_ "dfw enable refuses while dfw runs" dfw enable
for c in $A $B $L $D $N $MH $T $T2 $M2; do wait_rules $c || bad "no rules for $c"; done

say "the example: one rule opens one direction, IPv4 and IPv6"
yes_ "a -> b:5432 tcp" tcp $A "$(ip4 $B)" 5432
yes_ "a -> b:5432 udp" udp $A "$(ip4 $B)" 5432
yes_ "a -> b:5432 tcp over IPv6" tcp $A "[$(ip6 $B)]" 5432
no_ "a -> b:80 (port not allowed)" tcp $A "$(ip4 $B)" 80
yes_ "a -> $EXT (listed) ping" pings $A "$EXT"
yes_ "a -> $EXT (listed) http" web $A "$EXT"
no_ "a -> $EXT2 (internet, not listed)" web $A "$EXT2"
no_ "b -> a:5432 (no rule that way)" tcp $B "$(ip4 $A)" 5432
no_ "b -> a:5432 over IPv6" tcp $B "[$(ip6 $A)]" 5432
yes_ "b -> $EXT2 (internet)" web $B "$EXT2"
no_ "b -> lanhost:80 (internet excludes lan)" tcp $B "$(ip4 $L)" 80
yes_ "d -> lanhost:80 (rfc1918 out, lan in)" tcp $D "$(ip4 $L)" 80
no_ "d -> lanhost:80 over IPv6 (rfc1918 is IPv4 only)" tcp $D "[$(ip6 $L)]" 80
no_ "a -> gateway (host not listed)" pings $A "$(gw $A)"

say "no rule means no network"
no_ "n -> $EXT" pings $N "$EXT"
no_ "n -> lanhost:80" tcp $N "$(ip4 $L)" 80
no_ "d -> n:80 (d may send to rfc1918, but no rule lets n accept)" tcp $D "$(ip4 $N)" 80
no_ "n -> gateway" pings $N "$(gw $N)"
yes_ "loopback inside n still works" tcp $N 127.0.0.1 80

say "several filtered networks"
yes_ "plan shows both networks" sh -c "grep -q '^network $NET (bridge' $DIR/plan && grep -q '^network $TWO (bridge' $DIR/plan"
yes_ "t, on $TWO, -> $EXT" pings $T "$EXT"
no_ "t2, on $TWO with no rule, -> $EXT" pings $T2 "$EXT"
yes_ "m2, on both, -> b:5432 over $NET" tcp $M2 "$(ip4 $B)" 5432
yes_ "m2 -> t:80 over $TWO" tcp $M2 "$(ipon $T $TWO)" 80
no_ "t2 -> t:80 (no rule)" tcp $T2 "$(ipon $T $TWO)" 80
yes_ "both of m2's veths jump to its chains, none is dropped" sh -c "[ \"\$(nft list map bridge fw out_by_port | grep -o '$(key $M2)_out' | wc -l)\" = 2 ]"
no_ "$TWO's bridge is in the open set" sh -c "nft list set bridge fw open_bridges | grep -q br-$(docker network inspect -f '{{.Id}}' $TWO | cut -c1-12)"

say "on a live system, edits apply only through dfw apply"
echo "allow [n] -> $EXT" | save_rules $RULESD/n.rules
sleep 2
no_ "n -> $EXT after saving a rule in rules.d, before dfw apply" pings $N "$EXT"
dfw plan >"$DIR/plan2" 2>&1
yes_ "plan notes the rules differ from those applied" grep -q "run dfw apply" "$DIR/plan2"
yes_ "dfw apply" dfw apply
yes_ "n -> $EXT after dfw apply" pings $N "$EXT"
drop_rules $RULESD/n.rules
no_ "n -> $EXT after removing the rule and applying" pings $N "$EXT"
docker exec -d $A sh -c "while sleep 0.2; do echo tick; done | socat - TCP:$(ip4 $B):5432 >/tmp/rev 2>&1"
sleep 2
yes_ "long-lived a -> b:5432 connection up" sh -c "docker exec $A pgrep -f 'socat - TCP:$(ip4 $B)' >/dev/null"
echo "$MAIN" | grep -vF '[a] -> [b]' | write_rules $RULES
sleep 2
no_ "a -> b:5432 once its rule is removed" tcp $A "$(ip4 $B)" 5432
C1=$(docker exec $A grep -c tick /tmp/rev 2>/dev/null); sleep 2; C2=$(docker exec $A grep -c tick /tmp/rev 2>/dev/null)
no_ "the long-lived connection kept flowing after its rule was removed ($C1 -> $C2 lines)" sh -c "docker exec $A pgrep -f 'socat - TCP:$(ip4 $B)' >/dev/null && [ '$C2' -gt '$C1' ]"
docker exec $A pkill -f "socat - TCP:$(ip4 $B)" 2>/dev/null
echo "$MAIN" | write_rules $RULES
yes_ "a -> b:5432 once the rule is back" tcp $A "$(ip4 $B)" 5432
printf '%s\nallow [b] -> [a]:99999\n' "$MAIN" | save_rules $RULES
no_ "dfw apply with an error in the rules" sh -c "dfw apply >$DIR/apply 2>&1"
yes_ "the refusal names the line and changes nothing" sh -c "grep -q '$RULES:11: destination' $DIR/apply && grep -q 'nothing was changed' $DIR/apply"
yes_ "a -> b:5432 still allowed (the applied rules stay)" tcp $A "$(ip4 $B)" 5432

say "at start, valid rules are applied; invalid ones fall back to the last applied"
systemctl stop dfw
{ echo "$MAIN"; echo "allow [n] -> $EXT"; } | save_rules $RULES
systemctl start dfw
yes_ "n -> $EXT: the edited rules were applied at start" eventually pings $N "$EXT"
systemctl stop dfw
printf '%s\nallow [b] -> [a]:99999\n' "$MAIN" | save_rules $RULES
systemctl start dfw
yes_ "invalid rules at start are logged" logged "so the rules last applied are used"
yes_ "n -> $EXT still: the rules last applied are used" pings $N "$EXT"
yes_ "a -> b:5432 still allowed" tcp $A "$(ip4 $B)" 5432
echo "$MAIN" | write_rules $RULES
no_ "n -> $EXT once its rule is gone and applied" pings $N "$EXT"

say "one network: other networks are left alone"
yes_ "f, on $FREE with no rules, reaches the internet" web $F "$EXT2"
yes_ "a container on the default bridge reaches the internet" docker run --rm "$IMG" curl -s -m5 -o /dev/null "http://$EXT/"
no_ "mh -> f over $FREE (mh is filtered, so its other network is dropped)" tcp $MH "$(ipon $F $FREE)" 80
no_ "f -> mh over $FREE" tcp $F "$(ipon $MH $FREE)" 80
yes_ "mh on two networks is logged as an error" logged "container $MH: is also on network $FREE"
docker network create acc_new >/dev/null
docker run -d --name nw1 --network acc_new "$IMG" sleep infinity >/dev/null
yes_ "a network created after enable is left alone" eventually web nw1 "$EXT"
yes_ "its bridge is in the open set" sh -c "nft list set bridge fw open_bridges | grep -q br-$(docker network inspect -f '{{.Id}}' acc_new | cut -c1-12)"
yes_ "the filtered network's bridge is not" sh -c "! nft list set bridge fw open_bridges | grep -q br-$(docker network inspect -f '{{.Id}}' $NET | cut -c1-12)"
docker rm -f nw1 >/dev/null; docker network rm acc_new >/dev/null

# Rules for the containers the rest of the tests start.
# cat, not awk FILE FILE: mawk stops at a missing file (no systemd-resolved).
UP=$(cat /run/systemd/resolve/resolv.conf /etc/resolv.conf 2>/dev/null | awk '/^nameserver/ && $2 !~ /^127\./ {print $2; exit}')
[ -n "$UP" ] || bad "no non-loopback nameserver in resolv.conf: the dns checks can't run"
write_rules $RULESD/test.rules <<EOF
allow host -> [pubok]:80/tcp
allow [dn1] -> dns
allow [dn2] -> $EXT
allow [dn3] -> internet
allow [sp] -> lan
allow lan -> [squat]:5432
allow [ct-cli] -> 10.210.0.250:9999/udp, [ct-srv]:9999/udp
allow [kk] -> $EXT
allow [lat] -> $EXT
allow [fpl] -> $EXT
allow [internet] -> $EXT
allow [ic1] -> $EXT:icmp
allow lan -> [ic2]:icmp
EOF

say "icmp"
serve ic1
serve ic2
wait_rules ic1; wait_rules ic2
yes_ "ic1 -> $EXT:icmp: ping works" pings ic1 "$EXT"
no_ "ic1 -> $EXT: http (only icmp allowed)" web ic1 "$EXT"
yes_ "d -> ic2 (lan -> ic2:icmp): ping works" pings $D "$(ip4 ic2)"
no_ "d -> ic2:80 (only icmp accepted)" tcp $D "$(ip4 ic2)" 80
docker rm -f ic1 ic2 >/dev/null

say "published ports: only what the rules allow"
docker run -d --name pub --network $NET -p 18181:80 "$IMG" sh -c "$SERVE" >/dev/null
docker run -d --name pubok --network $NET -p 18182:80 "$IMG" sh -c "$SERVE" >/dev/null
wait_rules pub; wait_rules pubok
HOSTIP=$(ip -4 route get "$EXT" | sed -n 's/.* src \([0-9.]*\).*/\1/p')
yes_ "host -> pubok's published port (allow host -> [pubok]:80/tcp)" sh -c "[ \"\$(socat -T3 - TCP:$HOSTIP:18182,connect-timeout=3 </dev/null 2>/dev/null)\" = hi ]"
no_ "host -> pub's published port (no rule)" sh -c "[ \"\$(socat -T3 - TCP:$HOSTIP:18181,connect-timeout=3 </dev/null 2>/dev/null)\" = hi ]"
yes_ "the refused connection is marked, so no reply can make it established" sh -c "conntrack -L -p tcp -d $HOSTIP --dport 18181 2>/dev/null | grep -q 'mark=1073741824'"
docker rm -f pub pubok >/dev/null

say "dns: upstream DNS is opt-in"
serve dn1 --dns "$UP"
serve dn2 --dns "$UP"
serve dn3 --dns "$UP"
wait_rules dn1; wait_rules dn2; wait_rules dn3
lookup() { docker exec "$1" nslookup -timeout=3 -retry=1 example.com >/dev/null 2>&1; }
yes_ "dns target: lookups through $UP work" lookup dn1
no_ "no dns target: lookups through $UP" lookup dn2
yes_ "internet includes dns" lookup dn3
docker rm -f dn1 dn2 dn3 >/dev/null

say "[internet] is a container, not the internet zone"
docker run -d --name internet --network $NET "$IMG" sh -c "$SERVE" >/dev/null
wait_rules internet
yes_ "container [internet] -> $EXT" pings internet "$EXT"
no_ "a container named internet gets nothing from the zone: [internet] -> $EXT2" web internet "$EXT2"
docker rm -f internet >/dev/null

say "spoofed source IP or MAC is dropped"
serve sp --cap-add NET_ADMIN
wait_rules sp
yes_ "sp -> lanhost:80 from its own address" tcp sp "$(ip4 $L)" 80
docker exec sp ip addr add 10.210.0.200/24 dev eth0
no_ "spoofed source IP 10.210.0.200" sh -c "[ \"\$(docker exec sp socat -T3 - TCP:$(ip4 $L):80,bind=10.210.0.200,connect-timeout=3 </dev/null 2>/dev/null)\" = hi ]"
docker exec sp ip -6 addr add fd00:210::200/64 dev eth0 nodad
no_ "spoofed source IPv6" sh -c "[ \"\$(docker exec sp socat -T3 - TCP6:[$(ip6 $L)]:80,bind=[fd00:210::200],connect-timeout=3 </dev/null 2>/dev/null)\" = hi ]"
LV=$(ip -o link | awk -F'[ :@]+' -v i="$(nsenter -t "$(docker inspect -f '{{.State.Pid}}' $L)" -n ip -o link show eth0 | sed -n 's/.*@if\([0-9]*\).*/\1/p')" '$1==i {print $2}')
timeout 6 tcpdump -i "$LV" -n -l "arp and arp[14:4] = 0x0ad200c8" 2>/dev/null >"$DIR/arp" &
sleep 1
docker exec sp arping -c 2 -U -I eth0 -s 10.210.0.200 10.210.0.200 >/dev/null 2>&1
wait
no_ "gratuitous ARP for a stolen address reaches no one" grep -q . "$DIR/arp"
docker exec sp ip link set eth0 address 02:42:de:ad:be:ef
no_ "spoofed MAC" tcp sp "$(ip4 $L)" 80
docker rm -f sp >/dev/null

say "a restarted container gets new rules, and a peer's new IP is picked up"
OLDKEY=$(key $B) OLDIP=$(ip4 $B)
OLDPORT=$(nft -j list map bridge fw out_by_port | jq -r '.nftables[].map.elem? // empty | .[] | select(.[1].jump.target == "'"${OLDKEY}_out"'") | .[0]' | head -1)
docker stop -t 0 $B >/dev/null
docker run -d --name squat --network $NET --ip "$OLDIP" "$IMG" sh -c "$SERVE" >/dev/null
docker start $B >/dev/null
wait_rules $B; wait_rules squat; sleep 0.5
yes_ "b got a new IP ($OLDIP -> $(ip4 $B))" test "$(ip4 $B)" != "$OLDIP"
yes_ "a -> b at its new IP" tcp $A "$(ip4 $B)" 5432
no_ "a -> the container that took b's old IP" tcp $A "$OLDIP" 5432
no_ "b's old port is gone from the map" sh -c "nft -j list map bridge fw out_by_port | jq -e '.nftables[].map.elem? // empty | .[] | select(.[0] == \"$OLDPORT\")' >/dev/null"
docker rm -f squat >/dev/null

say "a stale UDP flow can't reach a new container that reuses the IP"
docker run -d --name ct-srv --network $NET --ip 10.210.0.250 "$IMG" sh -c "$SERVE" >/dev/null
docker run -d --name ct-cli --network $NET "$IMG" sh -c \
	'while :; do echo x | socat -T1 - UDP:10.210.0.250:9999,sourceport=40000,reuseaddr >>/tmp/replies; sleep 0.2; done' >/dev/null
wait_rules ct-srv; wait_rules ct-cli; sleep 2
yes_ "flow established" sh -c "docker exec ct-cli grep -q hi /tmp/replies"
docker rm -f ct-srv >/dev/null
docker run -d --name ct-new --network $NET --ip 10.210.0.250 "$IMG" sh -c 'timeout 6 tcpdump -n -i eth0 -c 1 udp port 9999 >/tmp/got 2>&1; sleep infinity' >/dev/null
sleep 7
no_ "the old flow's packets reach the new container" sh -c "docker exec ct-new grep -q 'UDP' /tmp/got"
docker rm -f ct-cli ct-new >/dev/null

say "with dfw run down, rules stay and new containers stay blocked"
systemctl stop dfw
yes_ "a -> b still allowed" tcp $A "$(ip4 $B)" 5432
serve kk
sleep 2
no_ "new container kk while dfw run is down" pings kk "$EXT"
systemctl start dfw
yes_ "kk gets its rules once dfw is back" wait_rules kk
yes_ "kk -> $EXT" pings kk "$EXT"
PID1=$(systemctl show -p MainPID --value dfw)
kill -9 "$PID1"
yes_ "a -> b allowed while dfw run is killed" tcp $A "$(ip4 $B)" 5432
sleep 3
yes_ "systemd restarted dfw run after a crash" sh -c "systemctl is-active -q dfw && [ \"\$(systemctl show -p MainPID --value dfw)\" != $PID1 ]"
docker rm -f kk >/dev/null

say "time until a new container's allowed traffic opens"
docker run -d --name lat --network $NET "$IMG" sh -c \
	"s=\$(cut -d' ' -f1 /proc/uptime); until socat -T1 - TCP:$EXT:80,connect-timeout=0.05 </dev/null >/dev/null 2>&1; do :; done; e=\$(cut -d' ' -f1 /proc/uptime); echo \$s \$e >/tmp/lat; sleep infinity" >/dev/null
sleep 8
echo "  opened after $(docker exec lat awk '{printf "%.2f s", $2-$1}' /tmp/lat 2>/dev/null || echo '?') (from the container's first instruction)"
docker rm -f lat >/dev/null

say "first packets of new containers never escape (${FIRST:-50} starts each)"
GW=$(gw $A)
WAN=$(ip -o route get "$EXT" | sed -n 's/.* dev \([^ ]*\).*/\1/p')
# Frames from containers already running (allowed ARP and such) don't count.
OLD=$(for c in $(docker ps -q --filter network=$NET); do printf ' and not ether src %s' "$(docker inspect -f "{{(index .NetworkSettings.Networks \"$NET\").MacAddress}}" "$c")"; done)
first() { # first SERVICE FILTER: start containers, capture on lanhost's veth and the uplink
	timeout 900 tcpdump -i "$WAN" -n -U -w "$DIR/wan.pcap" "udp port 9998" 2>/dev/null &
	local t1=$!
	timeout 900 tcpdump -i "$LV" -n -U -w "$DIR/peer.pcap" "$2" 2>/dev/null &
	local t2=$!
	sleep 1
	for _ in $(seq "${FIRST:-50}"); do
		docker run --rm --network $NET -l "com.docker.compose.service=$1" "$IMG" sh -c \
			"echo x | socat - UDP-DATAGRAM:10.210.0.255:9998,broadcast; echo x | socat - UDP:$(ip4 $L):9998; echo x | socat - UDP:$EXT2:9998; echo x | socat - UDP:$GW:9998" >/dev/null 2>&1
	done
	sleep 1; kill $t1 $t2 2>/dev/null; wait $t1 $t2 2>/dev/null
	local nw np
	nw=$(tcpdump -r "$DIR/wan.pcap" -n 2>/dev/null | wc -l) np=$(tcpdump -r "$DIR/peer.pcap" -n 2>/dev/null | wc -l)
	tcpdump -r "$DIR/peer.pcap" -n -e 2>/dev/null | head -3
	test "$nw$np" = 00
}
# Once a container has its chain, ARP and neighbour discovery are allowed for
# it; before that, nothing at all.
yes_ "unmentioned: nothing but ARP and ND escapes" first fpu "not arp and not (icmp6 and (ip6[40] == 135 or ip6[40] == 136)) and not ether src $(cat /sys/class/net/"$LV"/address)$OLD"
yes_ "allow [fpl] -> $EXT: nothing outside its rules escapes" first fpl "udp port 9998"

say "removal is refused while active; an upgrade drops no allowed connection"
docker exec -d $A sh -c "while sleep 0.2; do echo tick; done | socat - TCP:$(ip4 $B):5432 >/tmp/long 2>&1"
sleep 2
no_ "apt remove refused" sh -c "DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq dfw >/dev/null 2>&1"
yes_ "still installed" installed
PID1=$(systemctl show -p MainPID --value dfw)
dpkg -i "$DEB" >/dev/null 2>&1
PID2=$(systemctl show -p MainPID --value dfw)
yes_ "upgrade restarted dfw.service ($PID1 -> $PID2)" test "$PID1" != "$PID2" -a "$PID2" != 0
yes_ "upgrade kept the edited rules" grep -q "^network $NET" $RULES
C1=$(docker exec $A grep -c tick /tmp/long)
sleep 2
C2=$(docker exec $A grep -c tick /tmp/long)
yes_ "long-lived a -> b connection kept flowing ($C1 -> $C2 lines)" test "$C2" -gt "$C1"
yes_ "the long-lived connection's client is still running" sh -c "docker exec $A pgrep -f 'socat - TCP' >/dev/null"

say "nft flush ruleset is repaired without restarting dfw run"
PID1=$(systemctl show -p MainPID --value dfw)
nft flush ruleset
sleep 1
yes_ "table restored" sh -c "nft list table bridge fw >/dev/null"
yes_ "a's rules restored" has_rules $A
yes_ "a -> b still allowed" tcp $A "$(ip4 $B)" 5432
no_ "b -> a still blocked" tcp $B "$(ip4 $A)" 5432
yes_ "dfw run was not restarted" test "$(systemctl show -p MainPID --value dfw)" = "$PID1"
yes_ "repair logged" logged "restoring it"

say "Docker restart without dfw run: the boot table"
docker compose -p $P -f "$DIR/compose.yaml" down -t 0 >/dev/null 2>&1
systemctl stop dfw
nft delete table bridge fw
systemctl restart docker # also restores Docker's own rules, gone with the flush
yes_ "the drop-in's dfw init loaded the table" sh -c "nft list table bridge fw >/dev/null"
yes_ "it leaves the recorded bridges open" sh -c "nft list set bridge fw open_bridges | grep -q docker0"
yes_ "a container on the default bridge reaches the internet" docker run --rm "$IMG" curl -s -m5 -o /dev/null "http://$EXT/"

say "disable and remove"
yes_ "dfw disable" dfw disable
no_ "table gone" nft list table bridge fw
no_ "drop-in gone" test -f /etc/systemd/system/docker.service.d/dfw.conf
docker compose -p $P -f "$DIR/compose.yaml" up -d >/dev/null 2>&1
yes_ "an unmentioned container reaches the internet again" web $N "$EXT"
yes_ "apt remove works when disabled" sh -c "DEBIAN_FRONTEND=noninteractive apt-get remove -y -qq dfw >/dev/null 2>&1"

echo
[ $FAILED = 0 ] && echo "ACCEPTANCE: all checks passed" || echo "ACCEPTANCE: FAILURES"
exit $FAILED
