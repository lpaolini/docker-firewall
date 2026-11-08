#!/bin/sh
# A disposable Debian 13 VM for the gate and acceptance tests, for machines
# that must not run them on their own kernel. QEMU runs inside a container
# (KVM if /dev/kvm exists, else software emulation, which is slow but works).
#
#   test/vm.sh up [docker.io|docker-ce]   create, boot and provision the VM
#   test/vm.sh ssh [command]              run a command in the VM as root
#   test/vm.sh put FILE...                copy files to /root in the VM
#   test/vm.sh reboot                     reboot and wait for SSH
#   test/vm.sh down                       delete the VM
#
# State lives in $DFW_VM_DIR (default ~/.cache/dfw-vm).
set -eu
D=${DFW_VM_DIR:-$HOME/.cache/dfw-vm}
NAME=dfw-vm
IMG_URL=https://cloud.debian.org/images/cloud/trixie/latest/debian-13-generic-amd64.qcow2

ip() { docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' $NAME; }
sshopts() { echo "-q -i $D/id -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o ServerAliveInterval=30"; }
vssh() { ssh $(sshopts) -p 2222 root@"$(ip)" "$@"; }
wait_ssh() { timeout 900 sh -c "until ssh $(sshopts) -p 2222 root@$(ip) true 2>/dev/null; do sleep 5; done"; }

case "${1:-}" in
up)
	ENGINE=${2:-docker.io}
	mkdir -p "$D"
	docker image inspect dfw-qemu >/dev/null 2>&1 || printf '%s\n' 'FROM debian:trixie' \
		'RUN apt-get update && apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils genisoimage socat && rm -rf /var/lib/apt/lists/*' |
		docker build -q -t dfw-qemu - >/dev/null
	[ -f "$D/base.qcow2" ] || curl -sSfL -o "$D/base.qcow2" "$IMG_URL"
	[ -f "$D/id" ] || ssh-keygen -q -t ed25519 -N '' -f "$D/id"
	printf '#cloud-config\ndisable_root: false\nusers:\n  - name: root\n    ssh_authorized_keys: ["%s"]\n' "$(cat "$D/id.pub")" >"$D/user-data"
	printf 'instance-id: dfw-vm-%s\nlocal-hostname: dfwvm\n' "$(date +%s)" >"$D/meta-data"
	docker rm -f $NAME >/dev/null 2>&1 || true
	docker run --rm -v "$D":/vm -w /vm dfw-qemu sh -c 'rm -f disk.qcow2 seed.iso &&
		genisoimage -quiet -output seed.iso -volid cidata -joliet -rock user-data meta-data &&
		qemu-img create -q -f qcow2 -F qcow2 -b base.qcow2 disk.qcow2 12G'
	ACCEL="-accel tcg,thread=multi -cpu max"
	DEV=""
	[ -e /dev/kvm ] && ACCEL="-accel kvm -cpu host" DEV="--device /dev/kvm"
	# shellcheck disable=SC2086
	docker run -d --name $NAME $DEV -v "$D":/vm -w /vm dfw-qemu qemu-system-x86_64 $ACCEL -smp 3 -m 1536 \
		-display none -serial file:/vm/console.log -monitor unix:/vm/mon.sock,server,nowait \
		-drive file=disk.qcow2,if=virtio -drive file=seed.iso,if=virtio,media=cdrom \
		-netdev user,id=n0,hostfwd=tcp::2222-:22,hostfwd=tcp::18080-:18080 -device virtio-net-pci,netdev=n0 >/dev/null
	wait_ssh
	# The guest's Docker must not use the outer Docker's 172.17.0.0/16, or
	# replies to SSH clients on that network vanish into the guest's docker0.
	vssh "set -e; export DEBIAN_FRONTEND=noninteractive
		mkdir -p /etc/docker
		echo '{\"bip\": \"10.200.0.1/24\", \"default-address-pools\": [{\"base\": \"10.201.0.0/16\", \"size\": 24}]}' >/etc/docker/daemon.json
		apt-get update -qq
		apt-get install -y -qq nftables conntrack tcpdump jq socat curl >/dev/null
		if [ $ENGINE = docker-ce ]; then
			install -m 0755 -d /etc/apt/keyrings
			curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
			echo 'deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable' >/etc/apt/sources.list.d/docker.list
			apt-get update -qq
			apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-compose-plugin >/dev/null || apt-get install -y -qq -f >/dev/null
		else
			apt-get install -y -qq docker.io docker-compose >/dev/null || apt-get install -y -qq -f >/dev/null
		fi
		systemctl enable --now docker >/dev/null 2>&1
		printf 'FROM alpine:3.22\nRUN apk add --no-cache socat curl bind-tools tcpdump iproute2\n' | docker build -q -t dfw-tools - >/dev/null
		echo \"\$(uname -r), Docker \$(docker version --format '{{.Server.Version}}')\""
	;;
ssh) shift; vssh "$@" ;;
put) shift; scp $(sshopts) -P 2222 "$@" root@"$(ip)":/root/ ;;
reboot)
	vssh 'systemctl reboot' 2>/dev/null || true
	sleep 15
	wait_ssh
	;;
down) docker rm -f $NAME >/dev/null; rm -rf "$D" ;;
*) sed -n '2,13p' "$0"; exit 2 ;;
esac
