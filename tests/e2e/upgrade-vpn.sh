#!/bin/bash
# Upgrading a running v1.7 firewall to the package in /root/palisade: settings, devices and names carry on, and the VPN
# arrives switched off, with what it needs installed.
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

echo "== v1.7, set up, with a device and a speed test setting"
mkdir -p /root/oldx && curl -sL -o /root/old.tar.gz https://github.com/djgene01/Palisade/releases/download/v1.7/palisade-linux-x64.tar.gz && tar -xzf /root/old.tar.gz -C /root/oldx
sh /root/oldx/palisade/install.sh > /tmp/i1.log 2>&1; echo "   $(cat /opt/palisade/VERSION)"
for i in $(seq 1 30); do [ -S $SOCK ] && break; sleep 1; done
post /config/apply "$(get /config | jq '.setupComplete=true | .wanInterface="eth0" | .lanInterface="lan0"')" >/dev/null; A -X POST http://agent/config/confirm
post /names '[{"mac":"02:00:00:00:00:77","name":"Living room TV"}]' >/dev/null
post /speed/settings '{"enabled":false,"intervalMinutes":60}' >/dev/null
ip netns exec tv timeout 20 dhclient -1 -pf /run/tv.pid -lf /tmp/tv.leases eth0 >/dev/null 2>&1
tv=$(ip netns exec tv ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)
get /status >/dev/null; sleep 2

echo "== Upgrade with devices online"
sh /root/palisade/install.sh > /tmp/i2.log 2>&1 && pass "install.sh completes over v1.7" || { fail "install"; tail /tmp/i2.log; }
echo "   now $(cat /opt/palisade/VERSION)"
for i in $(seq 1 30); do get /vpn >/dev/null 2>&1 && break; sleep 1; done
command -v wg >/dev/null && pass "WireGuard's tools are installed" || fail "no wg"
get /vpn | jq -e '.problem == ""' >/dev/null && pass "the VPN answers" || fail "vpn: $(get /vpn)"
get /config | jq -e '.setupComplete and .lanInterface == "lan0" and (.vpn.enabled | not) and .names[0].name == "Living room TV"' >/dev/null && pass "settings kept, the VPN arrives switched off" || fail "config: $(get /config | jq -c '{setupComplete, lanInterface, vpn: .vpn.enabled, names}')"
get /speed | jq -e '.settings.intervalMinutes == 60' >/dev/null && pass "speed test settings kept" || fail "speed settings"
! ip link show palisade-wg >/dev/null 2>&1 && ! nft list ruleset | grep -q "dport 51820" && pass "nothing opened by the upgrade" || fail "something opened"
systemctl is-active --quiet dnsmasq && pass "the name server runs" || fail "dnsmasq down"
get /status >/dev/null; sleep 2
[ "$(dig +short @192.168.50.1 living-room-tv.home.arpa)" = "$tv" ] && pass "the TV keeps its name" || fail "name: '$(dig +short @192.168.50.1 living-room-tv.home.arpa)'"
ip netns exec tv dhclient -1 -pf /run/tv.pid -lf /tmp/tv.leases eth0 >/dev/null 2>&1
[ "$(ip netns exec tv ip -4 -o addr show dev eth0 | awk '{print $4}' | cut -d/ -f1)" = "$tv" ] && pass "the TV renews and keeps its address" || fail "renew"
echo; echo "RESULT: $PASSES passed, $FAILS failed"
