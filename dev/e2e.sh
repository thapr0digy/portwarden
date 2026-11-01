#!/usr/bin/env bash
# End-to-end check, run inside the VM as the dev user with sudo (make e2e).
#   1. latency: listen() on :8099 -> an OPENED line from lw-watch, must be <= 1000 ms;
#      closing it must produce CLOSED within 5 s.
#   2. efficiency: with kernel.bpf_stats_enabled=1, 10 000 real TCP connections accepted
#      by a python http.server must not run any of the agent's BPF programs.
# Self-contained: it builds its own binaries, runs its own nats-server on a private port
# and store, stops the lw-agent systemd unit while it runs (it would share the BPF
# programs' run counters) and puts everything back on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

NATS_PORT=4333
SERVER_PORT=8099
CONNECTIONS=10000
MAX_LATENCY_MS=1000
LINE_TIMEOUT_S=5
AGENT_PROGS='["on_listen","on_stop","owners"]'

work=$(mktemp -d)
nats_url="nats://127.0.0.1:$NATS_PORT"
pids=() # background children of this script (not the sudo-run agent)
agent_pid=""
unit_was_active=false
old_bpf_stats=""

log() { echo "e2e: $*"; }

fail() {
	echo "e2e: FAIL: $*" >&2
	for f in agent nats watch; do
		[ -s "$work/$f.log" ] && { echo "--- $f.log (tail) ---" >&2; tail -n 20 "$work/$f.log" >&2; }
	done
	exit 1
}

cleanup() {
	local status=$?
	trap - EXIT
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	if [ -n "$agent_pid" ]; then
		sudo pkill -TERM -f "$work/lw-agent" 2>/dev/null || true
		wait "$agent_pid" 2>/dev/null || true
	fi
	for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
	[ -n "$old_bpf_stats" ] && sudo sysctl -q kernel.bpf_stats_enabled="$old_bpf_stats" || true
	$unit_was_active && sudo systemctl start lw-agent || true
	rm -rf "$work"
	exit "$status"
}
trap cleanup EXIT

now_ns() { date +%s%N; }

# wait_for <description> <timeout seconds> <command...>: polls every 10 ms.
wait_for() {
	local what=$1 timeout=$2 deadline
	shift 2
	deadline=$(($(now_ns) + timeout * 1000000000))
	until "$@"; do
		[ "$(now_ns)" -lt "$deadline" ] || fail "timed out after ${timeout}s waiting for $what"
		sleep 0.01
	done
}

# seen <pattern> <count>: the watch output has at least <count> matching lines.
seen() { [ "$(grep -c -- "$1" "$work/watch.log" || true)" -ge "$2" ]; }

# agent_runs: "<name> <run_cnt> <run_time_ns>" for each of the agent's BPF programs.
agent_runs() {
	sudo bpftool prog show -j | jq -r --argjson names "$AGENT_PROGS" \
		'.[] | select(.name as $n | $names | index($n)) | "\(.name) \(.run_cnt // 0) \(.run_time_ns // 0)"' | sort
}

start_server() {
	python3 -m http.server "$SERVER_PORT" --bind 0.0.0.0 --directory "$work/www" >/dev/null 2>&1 &
	server_pid=$!
	pids+=("$server_pid")
}

stop_server() {
	kill "$server_pid"
	wait "$server_pid" 2>/dev/null || true
}

ss -Hltn "sport = :$SERVER_PORT" | grep -q . && fail "port $SERVER_PORT is already in use"
mkdir -p "$work/www"

log "building"
go build -o "$work/lw-agent" ./cmd/lw-agent
go build -o "$work/lw-watch" ./cmd/lw-watch

systemctl is-active --quiet lw-agent && unit_was_active=true
$unit_was_active && sudo systemctl stop lw-agent

nats-server -js -a 127.0.0.1 -p "$NATS_PORT" -sd "$work/js" >"$work/nats.log" 2>&1 &
pids+=($!)
wait_for "nats-server" 10 bash -c "exec 3<>/dev/tcp/127.0.0.1/$NATS_PORT" 2>/dev/null

sudo "$work/lw-agent" --nats-url "$nats_url" --heartbeat 1s >"$work/agent.log" 2>&1 &
agent_pid=$!
agent_alive() { kill -0 "$agent_pid" 2>/dev/null || fail "lw-agent exited early"; }
stream_ready() { agent_alive; nats --server "$nats_url" stream info ASM_EVENTS >/dev/null 2>&1; }
wait_for "stream ASM_EVENTS" 15 stream_ready

"$work/lw-watch" --nats-url "$nats_url" --since 0s >"$work/watch.log" 2>&1 &
pids+=($!)
# A heartbeat arriving proves the consumer is live before any listener is opened.
wait_for "first heartbeat in lw-watch" 10 seen HEARTBEAT 1

log "latency: listen on :$SERVER_PORT"
t0=$(now_ns)
start_server
wait_for "OPENED tcp 0.0.0.0:$SERVER_PORT" "$LINE_TIMEOUT_S" seen "OPENED tcp 0.0.0.0:$SERVER_PORT" 1
t1=$(now_ns)
latency_ms=$(((t1 - t0) / 1000000))
echo "opened latency: $latency_ms ms"

stop_server
wait_for "CLOSED tcp 0.0.0.0:$SERVER_PORT" "$LINE_TIMEOUT_S" seen "CLOSED tcp 0.0.0.0:$SERVER_PORT" 1
log "closed line seen"

[ "$latency_ms" -le "$MAX_LATENCY_MS" ] || fail "opened latency $latency_ms ms > $MAX_LATENCY_MS ms"

log "efficiency: $CONNECTIONS connections with bpf stats on"
old_bpf_stats=$(sysctl -n kernel.bpf_stats_enabled)
sudo sysctl -q kernel.bpf_stats_enabled=1
runs_start=$(agent_runs)
[ -n "$runs_start" ] || fail "no agent BPF programs found (expected $AGENT_PROGS)"

start_server
wait_for "second OPENED tcp 0.0.0.0:$SERVER_PORT" "$LINE_TIMEOUT_S" seen "OPENED tcp 0.0.0.0:$SERVER_PORT" 2
runs_before=$(agent_runs)
# Control: stats are live, so the listen() above must have run on_listen.
[ "$(awk '$1=="on_listen"{print $2}' <<<"$runs_before")" -gt "$(awk '$1=="on_listen"{print $2}' <<<"$runs_start")" ] ||
	fail "bpf stats control failed: on_listen run_cnt did not rise on listen()"

codes=$(curl -s -o /dev/null -w '%{http_code}\n' --max-time 120 "http://127.0.0.1:$SERVER_PORT/?[1-$CONNECTIONS]" | sort | uniq -c)
[ "$(awk '{print $2}' <<<"$codes")" = "200" ] && [ "$(awk '{print $1}' <<<"$codes")" = "$CONNECTIONS" ] ||
	fail "expected $CONNECTIONS HTTP 200 responses, got: $codes"
log "$CONNECTIONS connections answered with HTTP 200"
runs_after=$(agent_runs)

stop_server

read -r runs ns < <(paste -d' ' <(echo "$runs_before") <(echo "$runs_after") |
	awk '{runs += $5 - $2; ns += $6 - $3} END {print runs, ns}')
echo "bpf runs during load: $runs"
if [ "$runs" -gt 0 ]; then
	echo "average ns per run: $((ns / runs))"
else
	echo "average ns per run: n/a"
fi
[ "$runs" -eq 0 ] || fail "BPF programs ran $runs times during the connection load"

! grep -q '^GAP ' "$work/watch.log" || fail "lw-watch reported a GAP"
log "ok"
