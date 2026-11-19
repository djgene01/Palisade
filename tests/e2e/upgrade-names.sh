#!/bin/bash
# Upgrading a running v1.5.1 firewall: names devices already gave must survive, before any of them renews.
set -u
apt-get install -y -qq dnsutils >/dev/null 2>&1
SOCK=/run/palisade/agent.sock
A() { curl -s --unix-socket $SOCK "$@"; }
get() { A "http://agent$1"; }
post() { A -H 'Content-Type: application/json' -d "$2" "http://agent$1"; }
PASSES=0; FAILS=0
pass() { echo "PASS  $*"; PASSES=$((PASSES+1)); }; fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
ip link add lan0 type bridge; ip link set lan0 up
ip netns add tv; ip link add vtv type veth peer name eth0 netns tv
ip link set vtv master lan0; ip link set vtv up; ip netns exec tv ip link set eth0 address 02:00:00:00:00:77; ip netns exec tv ip link set eth0 up

echo "== v1.5.1"
mkdir -p /root/oldx && curl -sL -o /root/old.tar.gz https://github.com/djgene01/Palisade/releases/download/v1.5.1/palisade-linux-x64.tar.gz && tar -xzf /root/old.tar.gz -C /root/oldx && ln -s /root/oldx/palisade /root/old
sh /root/old/install.sh > /tmp/i1.log 2>&1 && cat /opt/palisade/VERSION
for i in $(seq 1 30); do [ -S $SOCK ] && break; sleep 1; done
post /config/apply "$(get /config | jq '.setupComplete=true | .wanInterface="eth0" | .lanInterface="lan0"')" >/dev/null; A -X POST http://agent/config/confirm
echo 'send host-name "living-room-tv";' > /tmp/tv.conf
ip netns exec tv timeout 20 dhclient -1 -cf /tmp/tv.conf -pf /run/tv.pid -lf /tmp/tv.leases eth0 >/dev/null 2>&1
tv=$(ip netns exec tv ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)
grep -q living-room-tv /var/lib/misc/dnsmasq.leases && echo "   v1.5.1 lease file has the name; tv at $tv"

echo "== upgrade, the TV does not renew"
sh /root/palisade/install.sh > /tmp/i2.log 2>&1 && cat /opt/palisade/VERSION
for i in $(seq 1 30); do get /status >/dev/null 2>&1 && break; sleep 1; done
# The upgrade re-applies the saved settings when the agent starts, which writes the new name server config.
grep -q "dhcp-script=/opt/palisade/palisade-lease-name" /etc/dnsmasq.d/palisade.conf && pass "name server now runs the lease script" || fail "no lease script in config"
test -x /opt/palisade/palisade-lease-name && pass "lease script installed" || fail "script missing"
get /status >/dev/null; sleep 2
[ "$(dig +short @192.168.50.1 living-room-tv.home.arpa)" = "$tv" ] && pass "the TV keeps its own name after the upgrade, without renewing" || fail "tv name: '$(dig +short @192.168.50.1 living-room-tv.home.arpa)' names=$(get /status | jq -c .names)"
[ "$(get /leases | jq -r '.[0].hostname')" = living-room-tv ] && pass "the Devices page still sees what the TV calls itself" || fail "lease hostname: $(get /leases | jq -c .)"
echo "== the TV renews"
ip netns exec tv dhclient -1 -cf /tmp/tv.conf -pf /run/tv.pid -lf /tmp/tv.leases eth0 >/dev/null 2>&1; sleep 1
[ "$(cat /var/lib/palisade/hostnames/02:00:00:00:00:77 2>/dev/null)" = living-room-tv ] && pass "the lease script records the name on renewal" || fail "script record"
[ "$(dig +short @192.168.50.1 living-room-tv.home.arpa)" = "$tv" ] && pass "still living-room-tv after the renewal" || fail "after renewal"
echo; echo "RESULT: $PASSES passed, $FAILS failed"
