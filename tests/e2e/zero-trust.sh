#!/bin/bash
# Zero Trust Mode end to end: the real release installed with install.sh, the real agent, nftables, dnsmasq and tcpdump,
# and two devices in their own network namespaces with real DHCP clients.
set -u
SOCK=/run/palisade/agent.sock
A() { curl -s --unix-socket $SOCK "$@"; }
get() { A "http://agent$1"; }
post() { A -H 'Content-Type: application/json' -d "$2" "http://agent$1"; }
confirm() { A -X POST http://agent/config/confirm; }
PASSES=0; FAILS=0
pass() { echo "PASS  $*"; PASSES=$((PASSES+1)); }
fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
check() { local what="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$what"; else fail "$what"; fi; }

HOME_MAC=02:00:00:00:00:01
STRANGER=02:00:00:00:00:aa

# The home port, a switch (bridge) with two devices on it.
ip link add lan0 type bridge; ip link set lan0 up
for d in home dev; do
    ip netns add $d
    ip link add v$d type veth peer name eth0 netns $d
    ip link set v$d master lan0; ip link set v$d up
    ip netns exec $d ip link set lo up
done
ip netns exec home ip link set eth0 address $HOME_MAC
ip netns exec dev ip link set eth0 address $STRANGER
ip netns exec home ip link set eth0 up
ip netns exec dev ip link set eth0 up

# dhclient per namespace, each with its own lease file. Prints the address it got, or nothing.
lease() {
    local ns=$1
    ip netns exec $ns dhclient -r -pf /run/dh-$ns.pid -lf /var/lib/dhcp/$ns.leases eth0 >/dev/null 2>&1
    rm -f /var/lib/dhcp/$ns.leases
    ip netns exec $ns ip -4 addr flush dev eth0
    ip netns exec $ns timeout 25 dhclient -1 -pf /run/dh-$ns.pid -lf /var/lib/dhcp/$ns.leases eth0 >/dev/null 2>&1
    ip netns exec $ns ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1
}

echo "== Install"
sh /root/palisade/install.sh > /tmp/install.log 2>&1 && pass "install.sh completes" || { fail "install.sh"; tail -20 /tmp/install.log; }
check "tcpdump installed" command -v tcpdump
check "curl installed" command -v curl
check "capture unit installed" test -f /etc/systemd/system/palisade-capture.service
for i in $(seq 1 30); do [ -S $SOCK ] && break; sleep 1; done

echo "== Set up the firewall"
cfg=$(get /config | jq '.setupComplete=true | .wanInterface="eth0" | .lanInterface="lan0" | .lanAddress="192.168.50.1" | .lanPrefix=24')
r=$(post /config/apply "$cfg"); echo "$r" | jq -e '.ok' >/dev/null && pass "setup applied" || fail "setup: $r"
confirm
home_ip=$(lease home)
[[ "$home_ip" == 192.168.50.* ]] && pass "home device leased $home_ip" || fail "home device lease: '$home_ip'"

echo "== Switch on"
r=$(post /zerotrust '{"enabled":true,"holdingAddress":"10.99.0.1","holdingPrefix":24}')
echo "$r" | jq -e '.ok and .confirmWithinSeconds > 0' >/dev/null && pass "switch-on waits for confirmation" || fail "switch-on: $r"
confirm
get /config | jq -e --arg m $HOME_MAC '.zeroTrust.enabled and any(.zeroTrust.approved[]; .mac==$m)' >/dev/null && pass "home device approved on switch-on" || fail "home not approved"
grep -q "$HOME_MAC" /etc/nftables.conf && pass "approved MAC in nftables.conf (boot)" || fail "nftables.conf lacks approved MAC"
check "capture service active" systemctl is-active --quiet palisade-capture
grep -q "$HOME_MAC" /etc/palisade/zt-hosts && pass "zt-hosts lists home device" || fail "zt-hosts"

echo "== A stranger joins"
s_ip=$(lease dev)
[[ "$s_ip" == 10.99.0.* ]] && pass "stranger held at $s_ip" || fail "stranger lease: '$s_ip'"
grep -q "option routers" /var/lib/dhcp/dev.leases && fail "holding lease carries a router" || pass "holding lease has no router"
grep -q "domain-name-servers" /var/lib/dhcp/dev.leases && fail "holding lease carries DNS" || pass "holding lease has no DNS server"
# A device that helps itself to a route anyway.
ip netns exec dev ip route add default via 10.99.0.1 2>/dev/null
ip netns exec dev nc -z -w 2 10.99.0.1 8080 && fail "stranger reached the web page" || pass "stranger can't reach the firewall's page"
ip netns exec dev nc -z -w 2 192.168.50.1 8080 && fail "stranger reached the home address" || pass "stranger can't reach the home address"
ip netns exec dev nc -z -w 2 1.1.1.1 443; ip netns exec dev nc -zu -w 1 10.99.0.1 53
ip netns exec dev ping -c 2 -W 1 $home_ip >/dev/null && fail "stranger pinged the home device through the firewall" || pass "stranger can't reach home device via firewall"
ip netns exec home nc -z -w 2 192.168.50.1 8080 && pass "home device still reaches the page" || fail "home device lost the page"
echo "   waiting for the agent to note the stranger..."
for i in $(seq 1 12); do get /status | jq -e --arg m $STRANGER 'any(.heldDevices[]; .mac==$m and (.flows|length)>0)' >/dev/null && break; sleep 5; done
get /status | jq -e --arg m $STRANGER 'any(.heldDevices[]; .mac==$m and (.flows|length)>0)' >/dev/null && pass "stranger listed as waiting, with flows" || { fail "stranger not in status"; get /status | jq -c '.heldDevices'; }
get /status | jq -c --arg m $STRANGER '.heldDevices[] | select(.mac==$m) | {address,attempts,flows:[.flows[]|"\(.protocol)/\(.address):\(.port)"]}'
get /status | jq -e --arg m $STRANGER 'any(.heldDevices[]; .mac==$m and (.hostname | length) > 0)' >/dev/null && pass "a waiting device shows what it calls itself" || fail "waiting device has no name"

echo "== Capture"
sleep 2
code=$(A -o /tmp/held.zip -w '%{http_code}' http://agent/held/capture)
[ "$code" = 200 ] && pass "capture download 200" || fail "capture download $code"
rm -rf /tmp/held && mkdir /tmp/held && unzip -q /tmp/held.zip -d /tmp/held && ls /tmp/held
ok=1; for f in /tmp/held/*; do case "$f" in *.pcap) ;; *) ok=0;; esac; tcpdump -r "$f" -c 1 >/dev/null 2>&1 || ok=0; done
[ $ok = 1 ] && [ -n "$(ls /tmp/held)" ] && pass "every capture entry is a readable .pcap" || fail "capture entries unreadable"
tcpdump -nr "$(ls /tmp/held/* | head -1)" 2>/dev/null | head -3
[ "$(stat -c %a /var/lib/palisade/capture)" = 700 ] && pass "capture folder is root-only" || fail "capture folder mode $(stat -c %a /var/lib/palisade/capture)"

echo "== Approve"
r=$(post /approvals "{\"action\":\"Approve\",\"mac\":\"$STRANGER\",\"name\":\"Visitor phone\"}")
echo "$r" | jq -e '.ok and (.confirmWithinSeconds // 0) == 0' >/dev/null && pass "approve needs no confirmation" || fail "approve: $r"
get /status | jq -e '.pendingSecondsLeft == null' >/dev/null && pass "nothing pending after approve" || fail "pending after approve"
nft list set inet palisade approved | grep -q $STRANGER && pass "live set holds the stranger" || fail "live set"
grep -q $STRANGER /etc/nftables.conf && pass "nftables.conf holds the stranger" || fail "nftables.conf after approve"
ip netns exec dev ip route del default 2>/dev/null
s_ip=$(lease dev)
[[ "$s_ip" == 192.168.50.* ]] && pass "approved device moves home ($s_ip)" || fail "approved lease: '$s_ip'"
ip netns exec dev nc -z -w 2 192.168.50.1 8080 && pass "approved device reaches the page" || fail "approved device can't reach page"

echo "== Remove approval"
r=$(post /approvals "{\"action\":\"Remove\",\"mac\":\"$STRANGER\"}")
echo "$r" | jq -e '.ok and .confirmWithinSeconds > 0' >/dev/null && pass "removal waits for confirmation" || fail "remove: $r"
confirm
ip netns exec dev nc -z -w 2 192.168.50.1 8080 && fail "removed device still reaches the page" || pass "removed device cut off at once"
s_ip=$(lease dev)
[[ "$s_ip" == 10.99.0.* ]] && pass "removed device back in holding ($s_ip)" || fail "removed lease: '$s_ip'"

echo "== Block"
r=$(post /approvals "{\"action\":\"Block\",\"mac\":\"$STRANGER\"}")
echo "$r" | jq -e '.ok' >/dev/null && pass "block applied" || fail "block: $r"
s_ip=$(lease dev)
[ -z "$s_ip" ] && pass "blocked device gets no address" || fail "blocked device leased '$s_ip'"

echo "== Unconfirmed switch-off is undone"
r=$(post /zerotrust '{"enabled":false}')
echo "$r" | jq -e '.ok' >/dev/null && pass "switch-off applied, pending" || fail "switch-off: $r"
check "capture stopped while pending" bash -c '! systemctl is-active --quiet palisade-capture'
echo "   waiting 70 s for the automatic undo..."
sleep 70
get /config | jq -e '.zeroTrust.enabled' >/dev/null && pass "mode back on after timeout" || fail "mode still off after timeout"
grep -q "set approved" /etc/nftables.conf && pass "nftables.conf restored" || fail "nftables.conf not restored"
grep -q "$STRANGER,ignore" /etc/palisade/zt-hosts && pass "zt-hosts restored with the block" || { fail "zt-hosts not restored"; cat /etc/palisade/zt-hosts; }
check "capture running again" systemctl is-active --quiet palisade-capture

echo "== Without the agent, at boot"
systemctl stop palisade-agent palisade-web
systemctl restart nftables dnsmasq
nft list set inet palisade approved | grep -q $HOME_MAC && pass "approvals loaded by nftables.service alone" || fail "approvals missing after restart"
s_ip=$(lease dev)
[ -z "$s_ip" ] && pass "block still enforced by dnsmasq alone" || fail "blocked device leased '$s_ip' after restart"
ip netns exec home nc -z -w 2 192.168.50.1 8080; home_ok=$?   # web is stopped; check the path, not the service
ip netns exec home ping -c 1 -W 1 192.168.50.1 >/dev/null && pass "home device still reaches the firewall" || fail "home device lost the firewall"
systemctl start palisade-agent palisade-web
for i in $(seq 1 30); do get /status >/dev/null 2>&1 && break; sleep 1; done

echo "== Emergency switch-off, as in the README"
curl -s --unix-socket /run/palisade/agent.sock -H 'Content-Type: application/json' -d '{"enabled":false}' http://agent/zerotrust
echo
curl -s --unix-socket /run/palisade/agent.sock -X POST http://agent/config/confirm
get /config | jq -e '.zeroTrust.enabled == false and .zeroTrust.holdingAddress == "10.99.0.1"' >/dev/null && pass "README commands switch it off, holding zone kept" || fail "README commands"
grep -q "set approved" /etc/nftables.conf && fail "nftables.conf still has Zero Trust" || pass "nftables.conf free of Zero Trust"
check "capture stopped" bash -c '! systemctl is-active --quiet palisade-capture'
[ -z "$(ls -A /var/lib/palisade/capture 2>/dev/null)" ] && pass "captures deleted" || fail "captures left: $(ls /var/lib/palisade/capture)"
s_ip=$(lease dev)
[[ "$s_ip" == 192.168.50.* ]] && pass "formerly blocked device gets a home address with the mode off" || fail "mode off lease: '$s_ip'"

echo
echo "RESULT: $PASSES passed, $FAILS failed"
