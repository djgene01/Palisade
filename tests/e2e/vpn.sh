#!/bin/bash
# The VPN with the real agent and real WireGuard on both ends. A small internet is built from network namespaces:
#   inet   the internet: a bridge, the provider's gateway 41.193.12.1, a server at 198.18.0.1, and Cloudflare's trace
#   phone1 out on mobile data, allowed home and internet       phone2 out there, allowed the internet only
#   home   a device at home on 192.168.50.x, which also uses the VPN from inside the house
set -u
apt-get install -y -qq wireguard-tools dnsutils python3 netcat-openbsd >/dev/null 2>&1
SOCK=/run/palisade/agent.sock
A() { curl -s --unix-socket $SOCK "$@"; }
get() { A "http://agent$1"; }
post() { A -H 'Content-Type: application/json' -d "$2" "http://agent$1"; }
confirm() { A -X POST http://agent/config/confirm; }
PASSES=0; FAILS=0
pass() { echo "PASS  $*"; PASSES=$((PASSES+1)); }; fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
ns() { ip netns exec "$@"; }
# Like a phone, which tries again by itself: WireGuard makes a fresh handshake within a few seconds of the firewall coming back.
retry() { for i in $(seq 1 10); do "$@" >/dev/null 2>&1 && return 0; sleep 2; done; return 1; }

echo "== Build the internet"
ip netns add inet; ns inet ip link set lo up
ns inet ip link add br0 type bridge; ns inet ip link set br0 up
ns inet ip addr add 41.193.12.1/24 dev br0; ns inet ip addr add 198.18.0.1/32 dev lo
ip link add wan0 type veth peer name i-fw; ip link set i-fw netns inet; ns inet ip link set i-fw master br0; ns inet ip link set i-fw up
for p in phone1:41.193.12.101 phone2:41.193.12.102; do
    n=${p%%:*}; a=${p##*:}
    ip netns add $n; ns $n ip link set lo up
    ip link add v-$n type veth peer name eth0 netns $n; ip link set v-$n netns inet
    ns inet ip link set v-$n master br0; ns inet ip link set v-$n up
    ns $n ip addr add $a/24 dev eth0; ns $n ip link set eth0 up; ns $n ip route add default via 41.193.12.1
done
ns inet sysctl -qw net.ipv4.ip_forward=1
# Cloudflare's trace, answering with whatever address it is told the firewall has.
mkdir -p /srv/cdn-cgi; echo "ip=41.193.12.57" > /srv/cdn-cgi/trace
ns inet python3 -m http.server 80 --bind 41.193.12.1 --directory /srv >/dev/null 2>&1 &
# A server out on the internet, which writes down where each connection came from.
ns inet python3 -c "import socketserver
class H(socketserver.BaseRequestHandler):
    def handle(self): open('/tmp/seen-from','a').write(self.client_address[0]+'\n'); self.request.sendall(b'hello\n')
socketserver.TCPServer(('198.18.0.1', 9000), H).serve_forever()" >/dev/null 2>&1 &

# The home network, with one device on it.
ip link add lan0 type bridge; ip link set lan0 up
ip netns add home; ns home ip link set lo up
ip link add v-home type veth peer name eth0 netns home; ip link set v-home master lan0; ip link set v-home up
ns home ip link set eth0 address 02:00:00:00:00:21; ns home ip link set eth0 up
printf 'iface wan0 inet manual\n' >> /etc/network/interfaces

echo "== Install, the internet port still on a private address"
sh /root/palisade/install.sh > /tmp/install.log 2>&1 || { echo "install failed"; tail /tmp/install.log; }
mkdir -p /etc/systemd/system/palisade-agent.service.d
printf '[Service]\nEnvironment=PALISADE_TRACE_URL=http://41.193.12.1/cdn-cgi/trace\n' > /etc/systemd/system/palisade-agent.service.d/trace.conf
systemctl daemon-reload; systemctl restart palisade-agent
for i in $(seq 1 30); do get /vpn >/dev/null 2>&1 && break; sleep 1; done
ip link set wan0 up; ip addr add 10.0.0.2/24 dev wan0; ip route replace default via 10.0.0.1 dev wan0
cfg=$(get /config | jq '.setupComplete=true | .wanInterface="wan0" | .lanInterface="lan0" | .filter.level="Security"')
post /config/apply "$cfg" | jq -e .ok >/dev/null || echo "   setup apply failed"; confirm
ns home timeout 20 dhclient -1 -pf /run/home.pid -lf /tmp/home.leases eth0 >/dev/null 2>&1
HOME_IP=$(ns home ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1); echo "   home device at $HOME_IP"

echo "== The check before anything opens"
post /vpn/check '{}' | jq -e '.outcome == "NotPublic"' >/dev/null && pass "a private address on the internet port is not ready" || fail "check: $(post /vpn/check '{}')"
post /vpn '{"enabled":true,"port":51820,"address":"10.66.0.1","prefix":24}' | jq -e '(.ok | not) and (.issues[0].message | contains("another router"))' >/dev/null \
    && pass "switching on is refused while it isn't ready" || fail "switched on regardless"
! ip link show palisade-wg >/dev/null 2>&1 && ! nft list ruleset | grep -q "dport 51820" && pass "nothing opened" || fail "something opened"

ip addr flush dev wan0; ip addr add 41.193.12.57/24 dev wan0; ip route replace default via 41.193.12.1 dev wan0
echo "ip=41.193.12.99" > /srv/cdn-cgi/trace
post /vpn/check '{}' | jq -e '.outcome == "Different"' >/dev/null && pass "a public address the internet doesn't see is not ready" || fail "different: $(post /vpn/check '{}')"
mv /srv/cdn-cgi/trace /srv/cdn-cgi/gone
post /vpn/check '{}' | jq -e '.outcome == "NoAnswer"' >/dev/null && pass "no answer from the outside service is not ready" || fail "no answer: $(post /vpn/check '{}')"
echo "ip=41.193.12.57" > /srv/cdn-cgi/trace
post /vpn/check '{}' | jq -e '.outcome == "Ready" and .portAddress == "41.193.12.57"' >/dev/null && pass "the firewall's own public address, as the internet sees it: ready" || fail "ready: $(post /vpn/check '{}')"

echo "== Switch on"
TOKEN=8b5e3f2a-1c4d-4e6f-9a0b-7c8d9e0f1a2b
r=$(post /vpn "{\"enabled\":true,\"port\":51820,\"address\":\"10.66.0.1\",\"prefix\":24,\"duckDnsName\":\"palisadetest\",\"duckDnsToken\":\"$TOKEN\"}")
echo "$r" | jq -e '.ok and .confirmWithinSeconds > 0' >/dev/null && pass "switching on waits for confirmation" || fail "on: $r"
confirm
wg show palisade-wg listen-port | grep -qx 51820 && pass "WireGuard listens on 51820" || fail "not listening"
[ "$(stat -c %a /etc/palisade/wireguard/server.key)" = 600 ] && [ "$(stat -c %a /etc/palisade/wireguard)" = 700 ] && pass "the firewall's key is root's alone" || fail "key modes"
[ "$(stat -c %a /var/lib/palisade/duckdns.json)" = 600 ] && pass "the DuckDNS token is root's alone" || fail "token mode"
get /vpn | jq -e '.duckDnsHasToken' >/dev/null && pass "pages see only that a token exists" || fail "hasToken"
SERVER_PUB=$(wg show palisade-wg public-key)

echo "== Add devices"
d1=$(post /vpn/devices '{"name":"Annas phone","access":"HomeAndInternet"}'); d2=$(post /vpn/devices '{"name":"Cafe laptop","access":"InternetOnly"}'); d3=$(post /vpn/devices '{"name":"Home tablet","access":"HomeAndInternet"}')
echo "$d1" | jq -e '.ok and .device.address == "10.66.0.2"' >/dev/null && echo "$d2" | jq -e '.device.address == "10.66.0.3"' >/dev/null && pass "three devices added at once" || fail "add: $d1"
get /status | jq -e '.pendingSecondsLeft == null' >/dev/null && pass "adding needs no confirmation" || fail "pending after add"
echo "$d1" | jq -r .clientConfig | grep -q "Endpoint = palisadetest.duckdns.org:51820" && pass "devices connect by the DuckDNS name" || fail "endpoint: $(echo "$d1" | jq -r .clientConfig | grep Endpoint)"
echo "$d1" | jq -r .clientConfig | grep -q "PublicKey = $SERVER_PUB" && pass "the settings carry the firewall's real key" || fail "server key"

# Bring a tunnel up by hand, as the WireGuard app does. The name is swapped for the address: there is no DuckDNS here.
up() {   # namespace, result, own address, endpoint
    local ns=$1 conf=/tmp/$1.conf
    echo "$2" | jq -r .clientConfig | grep -v '^Address\|^DNS\|^#' | sed "s/^Endpoint = .*/Endpoint = $4:51820/" > $conf
    ns $ns ip link add wg0 type wireguard; ns $ns wg setconf wg0 $conf; ns $ns ip addr add $3/32 dev wg0; ns $ns ip link set wg0 up
    for net in 10.66.0.0/24 192.168.50.0/24 198.18.0.1/32; do ns $ns ip route replace $net dev wg0; done
}
up phone1 "$d1" 10.66.0.2 41.193.12.57
up phone2 "$d2" 10.66.0.3 41.193.12.57

echo "== Home and internet (phone1, out on mobile data)"
ns phone1 ping -c 2 -W 2 10.66.0.1 >/dev/null && pass "the tunnel comes up" || fail "no tunnel"
ns phone1 ping -c 2 -W 2 $HOME_IP >/dev/null && pass "reaches the device at home" || fail "home device"
[ "$(ns phone1 curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://192.168.50.1:8080/)" != 000 ] && pass "reaches this firewall's page" || fail "page"
[ "$(ns phone1 dig +short +time=2 @10.66.0.1 palisade.home.arpa)" = 192.168.50.1 ] && pass "device names work" || fail "names"
[ "$(ns phone1 timeout 4 nc 198.18.0.1 9000 </dev/null)" = hello ] && pass "reaches the internet through the home line" || fail "internet"
tail -1 /tmp/seen-from | grep -qx 41.193.12.57 && pass "the internet sees the home line's address, not the tunnel's" || fail "seen from $(tail -1 /tmp/seen-from)"
# Filtered: a lookup sent to some other server is answered by the firewall all the same.
[ "$(ns phone1 dig +short +time=2 @198.18.0.1 palisade.home.arpa)" = 192.168.50.1 ] && pass "lookups to any server are answered by the firewall's filter" || fail "not redirected"
get /vpn | jq -e --arg id "$(echo "$d1" | jq -r .device.id)" 'any(.peers[]; .deviceId == $id and .lastHandshake != null and (.fromHome | not))' >/dev/null && pass "the page sees phone1 connected from outside" || fail "peer status: $(get /vpn | jq -c .peers)"

echo "== Internet only (phone2)"
[ "$(ns phone2 timeout 4 nc 198.18.0.1 9000 </dev/null)" = hello ] && pass "reaches the internet" || fail "internet only: no internet"
[ "$(ns phone2 dig +short +time=2 @10.66.0.1 palisade.home.arpa)" = 192.168.50.1 ] && pass "can look names up" || fail "no lookups"
! ns phone2 ping -c 2 -W 2 $HOME_IP >/dev/null && pass "can't reach the device at home" || fail "REACHED HOME"
[ "$(ns phone2 curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://192.168.50.1:8080/)" = 000 ] && [ "$(ns phone2 curl -s -o /dev/null -w '%{http_code}' --max-time 4 http://10.66.0.1:8080/)" = 000 ] && pass "can't reach this firewall's page, on any address" || fail "REACHED THE PAGE"
! ns phone2 timeout 4 bash -c 'echo > /dev/tcp/10.66.0.1/22' 2>/dev/null && pass "can't reach SSH" || fail "REACHED SSH"
! ns phone2 ping -c 2 -W 2 10.66.0.2 >/dev/null && pass "can't reach another VPN device" || fail "reached phone1"
# Pretending to be phone1 through its own tunnel: WireGuard drops it, since phone2 may only send as 10.66.0.3.
ns phone2 ip addr add 10.66.0.2/32 dev wg0
! ns phone2 ping -c 2 -W 2 -I 10.66.0.2 $HOME_IP >/dev/null && pass "a spoofed address gets nowhere" || fail "SPOOF WORKED"
ns phone2 ip addr del 10.66.0.2/32 dev wg0

echo "== A phone at home with its VPN still on"
ns home ip link add wg0 type wireguard
echo "$d3" | jq -r .clientConfig | grep -v '^Address\|^DNS\|^#' | sed "s/^Endpoint = .*/Endpoint = 41.193.12.57:51820/" > /tmp/home.conf
ns home wg setconf wg0 /tmp/home.conf; ns home ip addr add 10.66.0.4/32 dev wg0; ns home ip link set wg0 up; ns home ip route add 10.66.0.1/32 dev wg0
ns home ping -c 2 -W 2 10.66.0.1 >/dev/null && pass "it still works from inside the house" || fail "no tunnel from home"
get /vpn | jq -e --arg id "$(echo "$d3" | jq -r .device.id)" 'any(.peers[]; .deviceId == $id and .fromHome)' >/dev/null && pass "and the page knows it connected from home, which proves nothing" || fail "fromHome"

echo "== Nothing secret leaks"
SERVER_PRIV=$(cat /etc/palisade/wireguard/server.key)
leak=0
for secret in "$SERVER_PRIV" "$(echo "$d1" | jq -r .clientConfig | sed -n 's/^PrivateKey = //p')" "$(echo "$d2" | jq -r .clientConfig | sed -n 's/^PrivateKey = //p')" "$TOKEN"; do
    for where in "/var/lib/palisade/config.json" "/etc/nftables.conf" "/etc/dnsmasq.d/palisade.conf"; do grep -qF "$secret" $where && { echo "   LEAK in $where"; leak=1; }; done
    for call in /config /status /vpn; do get $call | grep -qF "$secret" && { echo "   LEAK in $call"; leak=1; }; done
    journalctl --no-pager | grep -qF "$secret" && { echo "   LEAK in the journal"; leak=1; }
done
ls /etc/palisade/wireguard | grep -qv '^server.key$' && { echo "   files left: $(ls /etc/palisade/wireguard)"; leak=1; }
[ $leak = 0 ] && pass "no private key or token in the config, the rules, the pages, the journal or leftover files" || fail "a secret leaked"

echo "== Removing a device ends it at once"
post /vpn/devices '{"name":"x","access":"HomeAndInternet"}' >/dev/null   # some churn
A -X DELETE "http://agent/vpn/devices/$(echo "$d1" | jq -r .device.id)" | jq -e .ok >/dev/null && pass "phone1 removed" || fail "remove"
! wg show palisade-wg peers | grep -qF "$(echo "$d1" | jq -r .device.publicKey)" && pass "its key is gone from WireGuard" || fail "key still there"
ns phone1 wg set wg0 peer "$SERVER_PUB" endpoint 41.193.12.57:51820   # force a fresh handshake attempt
! ns phone1 ping -c 3 -W 2 $HOME_IP >/dev/null && pass "phone1 reaches nothing any more" || fail "PHONE1 STILL IN"
ns phone2 ping -c 1 -W 2 10.66.0.1 >/dev/null && pass "the others carry on" || fail "others cut"

echo "== Switch off and back on"
post /vpn '{"enabled":false,"port":51820,"address":"10.66.0.1","prefix":24,"duckDnsName":"palisadetest"}' | jq -e .ok >/dev/null; confirm
! ip link show palisade-wg >/dev/null 2>&1 && ! nft list ruleset | grep -q "dport 51820" && pass "off: tunnel gone, port closed" || fail "off"
post /vpn '{"enabled":true,"port":51820,"address":"10.66.0.1","prefix":24,"duckDnsName":"palisadetest"}' | jq -e .ok >/dev/null; confirm
[ "$(wg show palisade-wg public-key)" = "$SERVER_PUB" ] && pass "back on with the same firewall key" || fail "server key changed"
retry ns phone2 ping -c 1 -W 2 10.66.0.1 && pass "a device added before still works without new settings" || fail "phone2 lost after off and on"

echo "== An unconfirmed switch-off is undone"
post /vpn '{"enabled":false,"port":51820,"address":"10.66.0.1","prefix":24,"duckDnsName":"palisadetest"}' | jq -e .ok >/dev/null
echo "   waiting 70 s for the undo..."; sleep 70
ip link show palisade-wg >/dev/null 2>&1 && retry ns phone2 ping -c 1 -W 2 10.66.0.1 && pass "the tunnel is back after the undo" || fail "not back"

echo "== Agent restart"
before=$(cat /sys/class/net/palisade-wg/ifindex)
systemctl restart palisade-agent; for i in $(seq 1 30); do get /vpn >/dev/null 2>&1 && break; sleep 1; done; sleep 2
[ "$(cat /sys/class/net/palisade-wg/ifindex)" = "$before" ] && pass "an agent restart leaves the tunnel alone (not even recreated)" || fail "tunnel recreated by a restart"
ns phone2 ping -c 2 -W 2 10.66.0.1 >/dev/null && pass "connected devices notice nothing" || fail "after restart"

echo "== The settings exactly as issued"
echo "$d2" | jq -r .clientConfig > /tmp/cafe-laptop.conf
! grep -q $'\r' /tmp/cafe-laptop.conf && wg-quick strip /tmp/cafe-laptop.conf >/dev/null 2>&1 && pass "WireGuard's own tools accept the file untouched" || fail "wg-quick refused the issued file"

echo "== Zero Trust and a filter level of its own, together with the VPN"
post /zerotrust '{"enabled":true,"holdingAddress":"10.99.0.1","holdingPrefix":24}' | jq -e .ok >/dev/null; confirm
cfg=$(get /config | jq '.filter.devices = [{"mac":"02:00:00:00:00:21","name":"Home tablet","level":"Family"}]')
post /config/apply "$cfg" | jq -e .ok >/dev/null || echo "   filter level apply failed"; confirm
retry ns phone2 ping -c 1 -W 2 10.66.0.1 && [ "$(ns phone2 timeout 4 nc 198.18.0.1 9000 </dev/null)" = hello ] && pass "VPN devices still reach the internet" || fail "VPN with Zero Trust"
[ "$(ns home timeout 4 nc 198.18.0.1 9000 </dev/null)" = hello ] && pass "the approved home device still reaches the internet" || fail "home device with Zero Trust"
retry ns home ping -c 1 -W 2 10.66.0.1 && pass "and its VPN from inside the house still works" || fail "home VPN with Zero Trust"
[ "$(ns phone2 dig +short +time=2 @10.66.0.1 palisade.home.arpa)" = 192.168.50.1 ] && pass "names still answer over the VPN" || fail "names with Zero Trust"

echo "== No DuckDNS name: after a restart, a new device still gets the real address"
post /vpn '{"enabled":true,"port":51820,"address":"10.66.0.1","prefix":24,"duckDnsName":""}' | jq -e .ok >/dev/null; confirm
systemctl restart palisade-agent; for i in $(seq 1 30); do get /vpn >/dev/null 2>&1 && break; sleep 1; done
d4=$(post /vpn/devices '{"name":"After restart","access":"InternetOnly"}')
echo "$d4" | jq -r .clientConfig | grep -qx "Endpoint = 41.193.12.57:51820" && pass "the address is checked afresh, never left empty" || fail "endpoint: $(echo "$d4" | jq -c '{ok, issues}') $(echo "$d4" | jq -r .clientConfig | grep Endpoint)"

echo "== A boot before the agent starts"
systemctl stop palisade-agent
ip link del palisade-wg 2>/dev/null
systemctl restart nftables dnsmasq; sleep 1
systemctl is-active --quiet dnsmasq && pass "the name server starts while the tunnel doesn't exist yet" || fail "dnsmasq failed: $(journalctl -u dnsmasq -n 3 --no-pager)"
ns home dhclient -1 -pf /run/home.pid -lf /tmp/home.leases eth0 >/dev/null 2>&1
[ "$(ns home dig +short +time=2 @192.168.50.1 palisade.home.arpa)" = 192.168.50.1 ] && pass "home devices still get addresses and names" || fail "home after boot"
systemctl start palisade-agent; for i in $(seq 1 30); do get /vpn >/dev/null 2>&1 && break; sleep 1; done; sleep 2
ip link show palisade-wg >/dev/null 2>&1 && retry ns phone2 ping -c 1 -W 2 10.66.0.1 && pass "the agent brings the tunnel back" || fail "tunnel not back after boot"

echo "== An unconfirmed switch-on is undone"
post /vpn '{"enabled":false,"port":51820,"address":"10.66.0.1","prefix":24,"duckDnsName":""}' | jq -e .ok >/dev/null; confirm
post /vpn '{"enabled":true,"port":51820,"address":"10.66.0.1","prefix":24,"duckDnsName":""}' | jq -e .ok >/dev/null
ip link show palisade-wg >/dev/null 2>&1 && pass "on while waiting for confirmation" || fail "not on"
echo "   waiting 70 s for the undo..."; sleep 70
! ip link show palisade-wg >/dev/null 2>&1 && ! nft list ruleset | grep -q "dport 51820" && pass "nobody confirmed: tunnel gone and port closed again" || fail "still open after the undo"

echo; echo "RESULT: $PASSES passed, $FAILS failed"
