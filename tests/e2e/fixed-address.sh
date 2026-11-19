#!/bin/bash
# Fixed addresses with the real agent: Zero Trust off, on, approving a device that already has one, and moving one.
set -u
SOCK=/run/palisade/agent.sock
A() { curl -s --unix-socket $SOCK "$@"; }
get() { A "http://agent$1"; }
post() { A -H 'Content-Type: application/json' -d "$2" "http://agent$1"; }
confirm() { A -X POST http://agent/config/confirm; }
PASSES=0; FAILS=0
pass() { echo "PASS  $*"; PASSES=$((PASSES+1)); }
fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
HOME_MAC=02:00:00:00:00:01; OTHER=02:00:00:00:00:aa

ip link add lan0 type bridge; ip link set lan0 up
for d in home dev; do
    ip netns add $d; ip link add v$d type veth peer name eth0 netns $d
    ip link set v$d master lan0; ip link set v$d up; ip netns exec $d ip link set lo up
done
ip netns exec home ip link set eth0 address $HOME_MAC; ip netns exec dev ip link set eth0 address $OTHER
ip netns exec home ip link set eth0 up; ip netns exec dev ip link set eth0 up
lease() {
    local ns=$1
    ip netns exec $ns dhclient -r -pf /run/dh-$ns.pid -lf /var/lib/dhcp/$ns.leases eth0 >/dev/null 2>&1
    rm -f /var/lib/dhcp/$ns.leases; ip netns exec $ns ip -4 addr flush dev eth0
    ip netns exec $ns timeout 25 dhclient -1 -pf /run/dh-$ns.pid -lf /var/lib/dhcp/$ns.leases eth0 >/dev/null 2>&1
    ip netns exec $ns ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1
}
# Fixes addresses the way the Devices page does: a whole config with the reservations changed.
fix() {
    local cfg; cfg=$(get /config | jq --argjson r "$1" '.dhcp.reservations = $r')
    r=$(post /config/apply "$cfg"); echo "$r" | jq -e '.ok' >/dev/null || echo "   apply: $r"
    confirm
}
res() { echo "[{\"name\":\"phone\",\"mac\":\"$HOME_MAC\",\"address\":\"$1\"}${2:+,{\"name\":\"tablet\",\"mac\":\"$OTHER\",\"address\":\"$2\"\}}]"; }

sh /root/palisade/install.sh > /tmp/install.log 2>&1 || { echo "install failed"; tail /tmp/install.log; }
for i in $(seq 1 30); do [ -S $SOCK ] && break; sleep 1; done
cfg=$(get /config | jq '.setupComplete=true | .wanInterface="eth0" | .lanInterface="lan0"')
post /config/apply "$cfg" >/dev/null; confirm

first=$(lease home); echo "   phone's first address from the range: $first"
fix "$(res 192.168.50.127)"
[ "$(lease home)" = 192.168.50.127 ] && pass "Zero Trust off: fixed address .127 given" || fail "off: not .127"

r=$(post /zerotrust '{"enabled":true,"holdingAddress":"10.99.0.1","holdingPrefix":24}'); confirm
grep -qx "$HOME_MAC,192.168.50.127" /etc/palisade/zt-hosts && pass "hosts file carries the fixed address" || { fail "hosts file"; cat /etc/palisade/zt-hosts; }
grep -q "^dhcp-host=" /etc/dnsmasq.d/palisade.conf && fail "main config still has a second entry" || pass "no second entry in the main config"
for i in 1 2 3; do got=$(lease home); [ "$got" = 192.168.50.127 ] || break; done
[ "$got" = 192.168.50.127 ] && pass "Zero Trust on: fixed address .127 kept over three renewals" || fail "on: got '$got'"

fix "$(res 192.168.50.140)"
[ "$(lease home)" = 192.168.50.140 ] && pass "Zero Trust on: moving the fixed address to .140 works" || fail "move: not .140"

# A waiting device given a fixed address stays held until approved, then gets that address.
fix "$(res 192.168.50.140 192.168.50.150)"
got=$(lease dev); [[ "$got" == 10.99.0.* ]] && pass "unapproved device with a fixed address stays held ($got)" || fail "unapproved got '$got'"
r=$(post /approvals "{\"action\":\"Approve\",\"mac\":\"$OTHER\",\"name\":\"tablet\"}")
[ "$(lease dev)" = 192.168.50.150 ] && pass "approving it gives its fixed address .150 at once" || fail "approved device not .150"
systemctl restart dnsmasq
[ "$(lease dev)" = 192.168.50.150 ] && [ "$(lease home)" = 192.168.50.140 ] && pass "both fixed addresses survive a dnsmasq restart" || fail "after restart"

echo; echo "RESULT: $PASSES passed, $FAILS failed"
