#!/bin/bash
# Speed tests with the real agent and Ookla's real program, fetched from Ookla. Runs two real tests (about 200 MB).
set -u
SOCK=/run/palisade/agent.sock
A() { curl -s --unix-socket $SOCK "$@"; }
get() { A "http://agent$1"; }
post() { A -H 'Content-Type: application/json' -d "$2" "http://agent$1"; }
PASSES=0; FAILS=0
pass() { echo "PASS  $*"; PASSES=$((PASSES+1)); }; fail() { echo "FAIL  $*"; FAILS=$((FAILS+1)); }
DIR=/var/lib/palisade/speedtest
wait_done() { for i in $(seq 1 75); do [ "$(get /speed | jq .running)" = false ] && return; sleep 2; done; }

sh /root/palisade/install.sh > /tmp/install.log 2>&1 || { echo "install failed"; tail /tmp/install.log; }
for i in $(seq 1 30); do [ -S $SOCK ] && break; sleep 1; done

echo "== Nothing runs before the owner accepts Ookla's terms"
get /speed | jq -e '.settings.termsAcceptedAt == null and .installed == false and (.history | length) == 0' >/dev/null && pass "starts with no terms, no program, no history" || fail "start: $(get /speed)"
post /speed/run '{}' | jq -e '.problem | contains("Accept")' >/dev/null && pass "a test by hand is refused until the terms are accepted" || fail "run without terms"
post /speed/settings '{"enabled":true,"intervalMinutes":30}' | jq -e '.problem | contains("Accept")' >/dev/null && pass "switching on is refused until the terms are accepted" || fail "enable without terms"
post /speed/settings '{"enabled":false,"intervalMinutes":7,"acceptTerms":true}' | jq -e '.problem | contains("how often")' >/dev/null && pass "an unknown interval is refused" || fail "interval"
[ ! -e $DIR/speedtest ] && pass "nothing was downloaded yet" || fail "downloaded early"

echo "== Accept, then test by hand"
post /speed/settings '{"enabled":false,"intervalMinutes":30,"acceptTerms":true}' | jq -e '.settings.termsAcceptedAt != null' >/dev/null && pass "terms accepted" || fail "accept"
post /speed/run '{}' | jq -e '.running' >/dev/null && pass "the test starts and the call returns at once" || fail "run"
wait_done
s=$(get /speed)
echo "   $(echo "$s" | jq -c '.history[0] | {down: (.downloadBps/1e6|floor), up: (.uploadBps/1e6|floor), ping: .pingMs, server, isp, mb: (.dataBytes/1e6|floor), problem}')"
echo "$s" | jq -e '.history[0] | .problem == "" and .downloadBps > 1e6 and .uploadBps > 1e6 and .pingMs > 0 and .trigger == "manual"' >/dev/null && pass "a real result: download, upload and ping" || fail "result: $(echo "$s" | jq -c '.history[0]')"
echo "$s" | jq -e '.history[0].resultUrl | startswith("https://www.speedtest.net/result/")' >/dev/null && pass "the shareable speedtest.net link is kept" || fail "no link"
echo "$s" | jq -e '.installed' >/dev/null && [ -x $DIR/speedtest ] && pass "Ookla's program was fetched and unpacked" || fail "program missing"
[ "$(stat -c %a $DIR/speedtest)" = 700 ] && pass "the program is root's alone" || fail "mode $(stat -c %a $DIR/speedtest)"
! grep -q "externalIp\|macAddr\|internalIp" /var/lib/palisade/speed.json && pass "the public address and hardware details are not stored" || fail "speed.json keeps identifying details"

echo "== A tampered program is never run; the schedule fetches the real one again"
printf '#!/bin/sh\ntouch /tmp/impostor-ran\necho "{\\"type\\":\\"result\\",\\"download\\":{\\"bandwidth\\":999999999}}"\n' > $DIR/speedtest; chmod 700 $DIR/speedtest
# No restart: the agent must catch a program changed under it, before the very next test.
post /speed/settings '{"enabled":true,"intervalMinutes":30}' | jq -e '.settings.enabled and .nextAt != null' >/dev/null && pass "automatic tests switched on, the next one planned" || fail "enable"
echo "   waiting for the scheduled test (about a minute)..."
for i in $(seq 1 60); do [ "$(get /speed | jq '.history | length')" -ge 2 ] && break; sleep 3; done
wait_done
s=$(get /speed)
echo "$s" | jq -e '.history[0] | .trigger == "scheduled" and .problem == "" and .downloadBps > 1e6 and .downloadBps < 7e9' >/dev/null && pass "the schedule ran a real test by itself" || fail "scheduled: $(echo "$s" | jq -c '.history[0]')"
[ ! -e /tmp/impostor-ran ] && pass "the impostor program never ran" || fail "THE IMPOSTOR RAN"
[ "$(sha256sum $DIR/speedtest | cut -d' ' -f1)" = "$(cat $DIR/speedtest.sha256)" ] && ! grep -q impostor $DIR/speedtest && pass "the real program is back" || fail "program not replaced"
echo "$s" | jq -e '.nextAt != null' >/dev/null && pass "the next test is planned 30 minutes on" || fail "no next"

echo "== Restart"
systemctl restart palisade-agent; for i in $(seq 1 30); do get /speed >/dev/null 2>&1 && break; sleep 1; done
get /speed | jq -e '(.history | length) == 2 and .settings.enabled and .settings.intervalMinutes == 30' >/dev/null && pass "history and settings survive a restart" || fail "after restart: $(get /speed | jq -c '{n: (.history|length), settings}')"

echo; echo "RESULT: $PASSES passed, $FAILS failed"
