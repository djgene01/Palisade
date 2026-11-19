#!/bin/bash
# System page end to end: the real agent's readings against free and df, a busy loop, and history across a restart.
set -u
SOCK=/run/palisade/agent.sock
get() { curl -s --unix-socket $SOCK "http://agent$1"; }
PASSES=0; FAILS=0
pass() { echo "PASS  $*"; PASSES=$((PASSES+1)); }
fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
near() { awk -v a="$1" -v b="$2" -v t="$3" 'BEGIN { d = a - b; if (d < 0) d = -d; exit !(d <= t) }'; }

sh /root/palisade/install.sh > /tmp/install.log 2>&1 && pass "install.sh completes" || { fail "install"; tail /tmp/install.log; }
for i in $(seq 1 30); do [ -S $SOCK ] && break; sleep 1; done
echo "   waiting 25 s for two readings..."
sleep 25
r=$(get "/health?range=Hour")
echo "$r" | jq -c '.now'
echo "$r" | jq -e '.now.cpuPercent != null' >/dev/null && pass "processor reading present before setup" || fail "no processor reading: $r"
echo "$r" | jq -e '(.points | length) >= 1 and .step == 60' >/dev/null && pass "hour history has minute points" || fail "no history"

mem_total=$(free -b | awk '/^Mem:/ {print $2}')
mem_used=$(( mem_total - $(free -b | awk '/^Mem:/ {print $7}') ))
near "$(echo "$r" | jq '.now.memoryTotal')" "$mem_total" 1 && pass "memory total matches free" || fail "memory total $(echo "$r" | jq '.now.memoryTotal') vs $mem_total"
near "$(echo "$r" | jq '.now.memoryUsed')" "$mem_used" 200000000 && pass "memory used matches free (within 200 MB)" || fail "memory used $(echo "$r" | jq '.now.memoryUsed') vs $mem_used"

read -r size used avail pcent <<<"$(df -B1 --output=size,used,avail,pcent / | tail -1 | tr -d '%')"
near "$(echo "$r" | jq '.now.diskTotal')" "$size" 1 && pass "disk total matches df" || fail "disk total $(echo "$r" | jq '.now.diskTotal') vs $size"
near "$(echo "$r" | jq '.now.diskUsed')" "$used" 100000000 && pass "disk used matches df (within 100 MB)" || fail "disk used $(echo "$r" | jq '.now.diskUsed') vs $used"
near "$(echo "$r" | jq '.now.diskPercent')" "$pcent" 1 && pass "disk share matches df's Use% ($pcent%)" || fail "disk % $(echo "$r" | jq '.now.diskPercent') vs $pcent"
[ "$(echo "$r" | jq '.now.cores')" = "$(nproc)" ] && pass "cores match nproc" || fail "cores"

cores=$(nproc)
idle=$(echo "$r" | jq '.now.cpuPercent')
echo "   busy loop on one core for 25 s (idle reading $idle%)..."
timeout 25 sh -c 'while :; do :; done' &
sleep 22
busy=$(get "/health?range=Hour" | jq '.now.cpuPercent')
wait
expected=$(awk -v c=$cores 'BEGIN { print 100 / c }')
awk -v b="$busy" -v i="$idle" -v e="$expected" 'BEGIN { exit !(b - i >= e * 0.6) }' && pass "one busy core raises processor use by about $expected% (was $idle%, now $busy%)" || fail "busy $busy vs idle $idle, expected +$expected"

echo "   restarting the agent..."
before=$(get "/health?range=Hour" | jq '.points | length')
systemctl restart palisade-agent
for i in $(seq 1 30); do get /health >/dev/null 2>&1 && break; sleep 1; done
test -s /var/lib/palisade/health.json && pass "history saved on stop" || fail "no health.json"
after=$(get "/health?range=Hour" | jq '.points | length')
[ "$after" -ge "$before" ] && pass "history kept across a restart ($before -> $after points)" || fail "history lost: $before -> $after"
systemctl stop palisade-agent
echo '{not json' > /var/lib/palisade/health.json
systemctl start palisade-agent
for i in $(seq 1 30); do get /health >/dev/null 2>&1 && break; sleep 1; done
systemctl is-active --quiet palisade-agent && pass "a corrupt history file doesn't stop the agent" || fail "agent died on corrupt file"
journalctl -u palisade-agent --no-pager | grep -q "starts afresh" && pass "corrupt file reported in the log" || fail "no log line"

echo
echo "RESULT: $PASSES passed, $FAILS failed"
