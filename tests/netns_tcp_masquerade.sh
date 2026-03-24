#!/bin/bash

set -euo pipefail

# This script exercises TCP outer transport with all active TCP conceal layers.
# It is Linux-only. AWG-specific options are configured through raw UAPI, so the
# local `wg` binary is only needed for key generation helpers.
#
# Usage:
#   ./netns_tcp_masquerade.sh <path to amneziawg-go> [shared-interface-fragment]
#
# The optional fragment file should contain only shared interface keys, e.g.
# Network / FormatIn / FormatOut / I1 / I2 / H1-H4 / S1-S4.
#
# The script verifies:
# - outer TCP stream contains the configured masquerade marker and decoys
# - an inner TCP payload sent over the tunnel is decrypted correctly
#
# Optional environment overrides:
#   OUTER_PORT1=10000 OUTER_PORT2=20000
#   FORMAT_MAGIC_HEX=feed
#   I1_HEX=aabb I2_HEX=ccdd
#   INNER_PORT=1111

exec 3>&1

program="${1:?usage: $0 <path to amneziawg-go>}"
shared_fragment="${2:-}"

: "${OUTER_PORT1:=10000}"
: "${OUTER_PORT2:=20000}"
: "${INNER_PORT:=1111}"
: "${FORMAT_MAGIC_HEX:=feed}"
: "${FORMAT_IN:=<b 0x${FORMAT_MAGIC_HEX}><dz be 2><d>}"
: "${FORMAT_OUT:=<b 0x${FORMAT_MAGIC_HEX}><dz be 2><d>}"
: "${I1_HEX:=aabb}"
: "${I2_HEX:=ccdd}"
: "${I1_RULES:=<b 0x${I1_HEX}>}"
: "${I2_RULES:=<b 0x${I2_HEX}>}"
: "${HEADER_COMPAT:=true}"
: "${S1:=15}"
: "${S2:=18}"
: "${S3:=20}"
: "${S4:=25}"
: "${H1:=123456-123500}"
: "${H2:=67543-67550}"
: "${H3:=223344-223350}"
: "${H4:=32345-32350}"

netns0="awg-tcp-test-$$-0"
netns1="awg-tcp-test-$$-1"
netns2="awg-tcp-test-$$-2"
tmpdir="$(mktemp -d /tmp/awg-tcp-test.XXXXXX)"
capture_file="$tmpdir/outer-tcpdump.txt"
recv_file="$tmpdir/inner-tcp.recv"
tcpdump_pid=""
server_pid=""

pretty() { echo -e "\x1b[32m\x1b[1m[+] ${1:+NS$1: }${2}\x1b[0m" >&3; }
pp() { pretty "" "$*"; "$@"; }
maybe_exec() { if [[ $BASHPID -eq $$ ]]; then "$@"; else exec "$@"; fi; }
n0() { pretty 0 "$*"; maybe_exec ip netns exec "$netns0" "$@"; }
n1() { pretty 1 "$*"; maybe_exec ip netns exec "$netns1" "$@"; }
n2() { pretty 2 "$*"; maybe_exec ip netns exec "$netns2" "$@"; }
ip0() { pretty 0 "ip $*"; ip -n "$netns0" "$@"; }
ip1() { pretty 1 "ip $*"; ip -n "$netns1" "$@"; }
ip2() { pretty 2 "ip $*"; ip -n "$netns2" "$@"; }

require_cmd() {
	command -v "$1" >/dev/null 2>&1 || {
		echo "missing required command: $1" >&2
		exit 1
	}
}

b64_to_hex() {
	printf '%s' "$1" | base64 -d | xxd -p -c 256
}

wait_file() {
	local ns=$1
	local path=$2
	local label=$3
	pretty "${ns//*-}" "wait for $label"
	while ! ip netns exec "$ns" test -S "$path"; do
		sleep 0.1
	done
}

wait_listener() {
	local ns=$1
	local port=$2
	local label=$3
	pretty "${ns//*-}" "wait for $label:$port"
	while ! ss -N "$ns" -tlH "sport = $port" | grep -q LISTEN; do
		sleep 0.1
	done
}

render_shared_interface() {
	if [[ -n $shared_fragment ]]; then
		cat "$shared_fragment"
		return
	fi

	cat <<EOF
Network = tcp
HeaderCompat = ${HEADER_COMPAT}
FormatIn = ${FORMAT_IN}
FormatOut = ${FORMAT_OUT}
I1 = ${I1_RULES}
I2 = ${I2_RULES}
S1 = ${S1}
S2 = ${S2}
S3 = ${S3}
S4 = ${S4}
H1 = ${H1}
H2 = ${H2}
H3 = ${H3}
H4 = ${H4}
EOF
}

render_shared_uapi() {
	if [[ -z $shared_fragment ]]; then
		cat <<EOF
network=tcp
header_compat=${HEADER_COMPAT}
format_in=${FORMAT_IN}
format_out=${FORMAT_OUT}
i1=${I1_RULES}
i2=${I2_RULES}
s1=${S1}
s2=${S2}
s3=${S3}
s4=${S4}
h1=${H1}
h2=${H2}
h3=${H3}
h4=${H4}
EOF
		return
	fi

	awk '
		function trim(s) {
			gsub(/^[ \t]+|[ \t]+$/, "", s)
			return s
		}
		BEGIN {
			map["Network"] = "network"
			map["FormatIn"] = "format_in"
			map["FormatOut"] = "format_out"
			map["HeaderCompat"] = "header_compat"
			map["I1"] = "i1"
			map["I2"] = "i2"
			map["I3"] = "i3"
			map["I4"] = "i4"
			map["I5"] = "i5"
			map["Jc"] = "jc"
			map["Jmin"] = "jmin"
			map["Jmax"] = "jmax"
			map["S1"] = "s1"
			map["S2"] = "s2"
			map["S3"] = "s3"
			map["S4"] = "s4"
			map["H1"] = "h1"
			map["H2"] = "h2"
			map["H3"] = "h3"
			map["H4"] = "h4"
		}
		/^[ \t]*(#|;|$)/ { next }
		/^[ \t]*\[/ { next }
		{
			line = $0
			sub(/\r$/, "", line)
			split(line, parts, "=")
			if (length(parts) < 2) {
				next
			}
			key = trim(parts[1])
			sub(/^[^=]*=/, "", line)
			value = trim(line)
			if (key in map) {
				printf "%s=%s\n", map[key], value
			}
		}
	' "$shared_fragment"
}

uapi_set() {
	local iface=$1
	local payload=$2
	local output
	output="$(
		printf 'set=1\n%s\n' "$payload" |
			ip netns exec "$netns0" socat - "UNIX-CONNECT:/var/run/amneziawg/${iface}.sock"
	)"
	if [[ "$output" != *"errno=0"* ]]; then
		echo "uapi set failed for $iface" >&2
		echo "$output" >&2
		return 1
	fi
}

render_base_uapi() {
	local private_key=$1
	local listen_port=$2
	local peer_pub=$3
	local psk=$4
	local allowed_ip=$5

	cat <<EOF
private_key=${private_key}
listen_port=${listen_port}
$(render_shared_uapi)
replace_peers=true
public_key=${peer_pub}
preshared_key=${psk}
protocol_version=1
replace_allowed_ips=true
allowed_ip=${allowed_ip}
EOF
}

render_endpoint_uapi() {
	local peer_pub=$1
	local endpoint=$2

	cat <<EOF
public_key=${peer_pub}
endpoint=${endpoint}
EOF
}

cleanup() {
	set +e
	exec 2>/dev/null

	if [[ -n $tcpdump_pid ]]; then
		kill -INT "$tcpdump_pid"
		wait "$tcpdump_pid"
	fi

	if [[ -n $server_pid ]]; then
		kill "$server_pid"
		wait "$server_pid"
	fi

	ip1 link del dev wg1
	ip2 link del dev wg2

	local to_kill
	to_kill="$(ip netns pids "$netns0") $(ip netns pids "$netns1") $(ip netns pids "$netns2")"
	[[ -n $to_kill ]] && kill $to_kill

	pp ip netns del "$netns1"
	pp ip netns del "$netns2"
	pp ip netns del "$netns0"
	rm -rf "$tmpdir"
}
trap cleanup EXIT

require_cmd ip
require_cmd ss
require_cmd wg
require_cmd base64
require_cmd xxd
require_cmd socat
require_cmd tcpdump

if [[ $EUID -ne 0 ]]; then
	echo "run as root" >&2
	exit 1
fi

if [[ -n $shared_fragment && ! -f $shared_fragment ]]; then
	echo "shared interface fragment not found: $shared_fragment" >&2
	exit 1
fi

ip netns del "$netns0" 2>/dev/null || true
ip netns del "$netns1" 2>/dev/null || true
ip netns del "$netns2" 2>/dev/null || true

pp ip netns add "$netns0"
pp ip netns add "$netns1"
pp ip netns add "$netns2"

ip0 link set up dev lo
ip1 link set up dev lo
ip2 link set up dev lo

n0 "$program" wg1
wait_file "$netns0" /var/run/amneziawg/wg1.sock "UAPI socket wg1"
ip0 link set wg1 netns "$netns1"

n0 "$program" wg2
wait_file "$netns0" /var/run/amneziawg/wg2.sock "UAPI socket wg2"
ip0 link set wg2 netns "$netns2"

key1_b64="$(pp wg genkey)"
key2_b64="$(pp wg genkey)"
pub1_b64="$(pp wg pubkey <<<"$key1_b64")"
pub2_b64="$(pp wg pubkey <<<"$key2_b64")"
psk_b64="$(pp wg genpsk)"

key1="$(b64_to_hex "$key1_b64")"
key2="$(b64_to_hex "$key2_b64")"
pub1="$(b64_to_hex "$pub1_b64")"
pub2="$(b64_to_hex "$pub2_b64")"
psk="$(b64_to_hex "$psk_b64")"

ip1 addr add 192.168.241.1/24 dev wg1
ip2 addr add 192.168.241.2/24 dev wg2

cfg1="$tmpdir/wg1.conf"
cfg2="$tmpdir/wg2.conf"
cat >"$cfg1" <<EOF
$(render_base_uapi "$key1" "$OUTER_PORT1" "$pub2" "$psk" "192.168.241.2/32")
EOF
cat >"$cfg2" <<EOF
$(render_base_uapi "$key2" "$OUTER_PORT2" "$pub1" "$psk" "192.168.241.1/32")
EOF

uapi_set wg1 "$(cat "$cfg1")"
uapi_set wg2 "$(cat "$cfg2")"

ip1 link set up dev wg1
ip2 link set up dev wg2

wait_listener "$netns0" "$OUTER_PORT1" "outer tcp listen"
wait_listener "$netns0" "$OUTER_PORT2" "outer tcp listen"

# Endpoint parsing must happen after the interface is up, otherwise it is still
# interpreted by the default UDP bind.
uapi_set wg1 "$(render_endpoint_uapi "$pub2" "127.0.0.1:${OUTER_PORT2}")"
uapi_set wg2 "$(render_endpoint_uapi "$pub1" "127.0.0.1:${OUTER_PORT1}")"

pretty 0 "capture outer tcp stream"
ip netns exec "$netns0" tcpdump -i lo -nn -s 0 -l -XX "tcp port ${OUTER_PORT1} or tcp port ${OUTER_PORT2}" >"$capture_file" 2>&1 &
tcpdump_pid=$!
sleep 1

pretty 2 "start inner tcp receiver on 192.168.241.2:${INNER_PORT}"
ip netns exec "$netns2" socat -T 10 -u "TCP-LISTEN:${INNER_PORT},bind=192.168.241.2,reuseaddr" - >"$recv_file" &
server_pid=$!
wait_listener "$netns2" "$INNER_PORT" "inner tcp listen"

payload="masked tcp over awg conceal $(date +%s)"
pretty 1 "send inner tcp payload to 192.168.241.2:${INNER_PORT}"
printf '%s' "$payload" | ip netns exec "$netns1" socat -T 10 -u - "TCP:192.168.241.2:${INNER_PORT},connect-timeout=10"
wait "$server_pid"
server_pid=""

recv_payload="$(cat "$recv_file")"
[[ "$recv_payload" == "$payload" ]]
pretty "" "inner tcp payload decrypted correctly"

sleep 1
kill -INT "$tcpdump_pid"
wait "$tcpdump_pid" || true
tcpdump_pid=""

capture_lc="$(tr '[:upper:]' '[:lower:]' <"$capture_file")"
[[ "$capture_lc" == *"$FORMAT_MAGIC_HEX"* ]]
[[ "$capture_lc" == *"$I1_HEX"* ]]
[[ "$capture_lc" == *"$I2_HEX"* ]]

pretty "" "outer tcp capture contains format magic ${FORMAT_MAGIC_HEX} and prelude decoys ${I1_HEX}/${I2_HEX}"
