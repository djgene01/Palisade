#!/bin/bash
# Device names with the real agent, real dnsmasq and real DHCP clients.
set -u
apt-get install -y -qq dnsutils >/dev/null 2>&1
SOCK=/run/palisade/agent.sock
A() { curl -s --unix-socket $SOCK "$@"; }
get() { A "http://agent$1"; }
post() { A -H 'Content-Type: application/json' -d "$2" "http://agent$1"; }
confirm() { A -X POST http://agent/config/confirm; }
PASSES=0; FAILS=0
pass() { echo "PASS  $*"; PASSES=$((PASSES+1)); }
fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
# Four devices: a phone that names itself, a second one with the same name, one that claims to be the firewall,
# and a camera that gives no name (its maker comes from the web's lookups).
declare -A MAC=( [phone]=02:00:00:00:00:01 [phone2]=02:00:00:00:00:02 [liar]=02:00:00:00:00:03 [camera]=00:16:6c:00:3f:2a )
declare -A HOST=( [phone]=pixel-7 [phone2]=pixel-7 [liar]=palisade [camera]="" )
ip link add lan0 type bridge; ip link set lan0 up
for d in phone phone2 liar camera; do
    ip netns add $d; ip link add v$d type veth peer name eth0 netns $d
    ip link set v$d master lan0; ip link set v$d up; ip netns exec $d ip link set lo up
    ip netns exec $d ip link set eth0 address ${MAC[$d]}; ip netns exec $d ip link set eth0 up
done
lease() {
    local ns=$1 conf=/tmp/dh-$1.conf
    if [ -n "${HOST[$ns]}" ]; then echo "send host-name \"${HOST[$ns]}\";" > $conf; else : > $conf; fi
    ip netns exec $ns dhclient -r -cf $conf -pf /run/dh-$ns.pid -lf /var/lib/dhcp/$ns.leases eth0 >/dev/null 2>&1
    rm -f /var/lib/dhcp/$ns.leases; ip netns exec $ns ip -4 addr flush dev eth0
    ip netns exec $ns timeout 25 dhclient -1 -cf $conf -pf /run/dh-$ns.pid -lf /var/lib/dhcp/$ns.leases eth0 >/dev/null 2>&1
    ip netns exec $ns ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1
}
q() { ip netns exec phone dig +short +tries=1 +time=2 @192.168.50.1 ${2:+-p $2} "$1"; }

sh /root/palisade/install.sh > /tmp/install.log 2>&1 || { echo "install failed"; tail /tmp/install.log; }
mkdir -p /var/lib/palisade-web && echo '{"00166C":"Samsung Electronics Co.,Ltd"}' > /var/lib/palisade-web/makers.json
for i in $(seq 1 30); do [ -S $SOCK ] && break; sleep 1; done
cfg=$(get /config | jq '.setupComplete=true | .wanInterface="eth0" | .lanInterface="lan0"')
post /config/apply "$cfg" >/dev/null; confirm

declare -A IP
for d in phone phone2 liar camera; do IP[$d]=$(lease $d); done
echo "   addresses: phone ${IP[phone]}, phone2 ${IP[phone2]}, liar ${IP[liar]}, camera ${IP[camera]}"
get /status >/dev/null; sleep 2   # a status request refreshes the names at once
echo "   names: $(get /status | jq -c '[.names[] | .name]')"
[ "$(q palisade.home.arpa)" = 192.168.50.1 ] && pass "palisade.home.arpa is the firewall" || fail "palisade: '$(q palisade.home.arpa)'"
[ "$(q pixel-7.home.arpa)" = "${IP[phone]}" ] && pass "pixel-7.home.arpa is the first phone" || fail "pixel-7: '$(q pixel-7.home.arpa)'"
[ "$(q pixel-7-2.home.arpa)" = "${IP[phone2]}" ] && pass "the second phone with the same name is pixel-7-2" || fail "pixel-7-2: '$(q pixel-7-2.home.arpa)'"
[ "$(q palisade-2.home.arpa)" = "${IP[liar]}" ] && pass "a device calling itself palisade gets palisade-2, not the firewall's name" || fail "liar: '$(q palisade-2.home.arpa)'"
[ "$(q palisade.home.arpa | wc -l)" = 1 ] && pass "palisade.home.arpa has exactly one answer" || fail "palisade answers: $(q palisade.home.arpa | tr '\n' ' ')"
# The container runs with the hostname "palisade", like a firewall named after its software.
if [ "$(hostname)" = palisade ]; then
    [ "$(q palisade)" = 192.168.50.1 ] && pass "bare palisade is only the home address, even on a machine called palisade" || fail "bare palisade: $(q palisade | tr '\n' ' ')"
fi
[ "$(q samsung-3f2a.home.arpa)" = "${IP[camera]}" ] && pass "a nameless camera is samsung-3f2a" || fail "camera: '$(q samsung-3f2a.home.arpa)'"
[ "$(q pixel-7)" = "${IP[phone]}" ] && pass "the short name works too" || fail "short name"
[ "$(ip netns exec phone dig +short @192.168.50.1 -x ${IP[phone]})" = pixel-7.home.arpa. ] && pass "reverse lookup gives the name" || fail "reverse"
grep -q "search home.arpa\|domain home.arpa" /var/lib/dhcp/phone.leases /etc/resolv.conf 2>/dev/null || grep -q 'domain-name "home.arpa"' /var/lib/dhcp/phone.leases && pass "devices are told the home.arpa domain" || fail "no domain in the lease"
st=$(ip netns exec phone dig @192.168.50.1 nothere.home.arpa | grep -o 'status: [A-Z]*')
[ "$st" = "status: NXDOMAIN" ] && pass "an unknown home.arpa name stays at home" || fail "unknown: $st"

echo "== Rename on the Devices page"
post /names "[{\"mac\":\"${MAC[phone]}\",\"name\":\"Gran's tablet\"}]" >/dev/null
get /status >/dev/null; sleep 2
[ "$(q grans-tablet.home.arpa)" = "${IP[phone]}" ] && pass "renamed device answers as grans-tablet within seconds" || fail "rename: '$(q grans-tablet.home.arpa)'"
[ -z "$(q pixel-7.home.arpa)" ] && pass "its old name is gone" || fail "old name still answers"
[ "$(q pixel-7-2.home.arpa)" = "${IP[phone2]}" ] && pass "the other phone keeps pixel-7-2 (no swap)" || fail "phone2 changed"

echo "== Per-device filter level (its own name server)"
cfg=$(get /config | jq --arg m ${MAC[phone]} '.filter.level="Security" | .filter.devices=[{"mac":$m,"name":"Grans tablet","level":"Family"}]')
r=$(post /config/apply "$cfg"); echo "$r" | jq -e .ok >/dev/null || echo "   apply: $r"; confirm
port=$(grep -h "^port=" /etc/palisade/dns/*.conf 2>/dev/null | head -1 | cut -d= -f2)
[ -n "$port" ] && [ "$(q grans-tablet.home.arpa $port)" = "${IP[phone]}" ] && pass "the per-level name server (port $port) answers names too" || fail "instance port '$port'"
[ "$(q pixel-7-2.home.arpa)" = "${IP[phone2]}" ] && pass "names still answer through the filter redirect" || fail "after filter"

echo "== Zero Trust"
r=$(post /zerotrust '{"enabled":true}'); confirm
post /approvals "{\"action\":\"Remove\",\"mac\":\"${MAC[liar]}\"}" >/dev/null; confirm
get /status >/dev/null; sleep 2
[ -z "$(q palisade-2.home.arpa)" ] && pass "a device whose approval is removed loses its name" || fail "unapproved still named"
[ "$(q grans-tablet.home.arpa $port)" = "${IP[phone]}" ] || [ "$(q grans-tablet.home.arpa)" = "${IP[phone]}" ] && pass "approved devices keep their names" || fail "approved lost name"

echo "== Restart"
systemctl restart palisade-agent; for i in $(seq 1 30); do get /status >/dev/null 2>&1 && break; sleep 1; done; sleep 2
jq -e 'length >= 4' /var/lib/palisade/names.json >/dev/null && pass "names kept in names.json" || fail "names.json"
[ "$(q pixel-7-2.home.arpa)" = "${IP[phone2]}" ] && pass "names unchanged after an agent restart" || fail "after restart"
ls -a /etc/palisade/names | grep -q palisade-tmp && fail "a temporary file was left in the names folder" || pass "no temporary file left behind"

echo; echo "RESULT: $PASSES passed, $FAILS failed"
