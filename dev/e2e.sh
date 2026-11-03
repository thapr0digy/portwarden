#!/usr/bin/env bash
# End-to-end check, run inside the VM as the dev user with sudo (make e2e).
#   1. latency: listen() on :8099 -> an OPENED line from portwarden-watch, must be <= 1000 ms;
#      closing it must produce CLOSED within 5 s. Same for a UDP bind() on :8098.
#   2. restart: restarting a transient unit serving :8097 gives one OWNER_CHANGED and no
#      CLOSED within 3 s.
#   3. container netns: a listener in a fresh netns carries netns=<n>, not the host's.
#   4. socket activation: once a recheck has run, :22 (ssh.socket) shows unit=ssh.service
#      sock=ssh.socket; SKIP when ssh.socket is not active.
#   5. efficiency: with kernel.bpf_stats_enabled=1, 10 000 real TCP connections accepted
#      by a python http.server must not run on_listen or on_stop; 1000 UDP client sockets
#      run on_udp_bind/on_udp_unhash (average ns per run printed) but produce no event.
#   6. exposure: :8093 behind an nft drop rule opens at level bound; inserting an accept
#      rule moves it to host_firewall_open (exposure.changed) within 5 s.
#   7. docker: a container listener published with -p 18090:80 reaches host_firewall_open;
#      a DOCKER-USER drop for it brings it back to bound, removing the drop restores it.
#      SKIP when docker or the busybox image is unavailable.
#   8. spool: with nats-server down, a listener opened on :8095 survives an agent restart in
#      the spool and reaches a fresh watcher (--since 5m) with its original time.
#   9. proxy: an nginx (its own transient unit) proxying :8080 to a backend on 127.0.0.1:18081
#      gives a proxy.routes event naming the backend program with [config]; real requests
#      through it make the backend [config,seen]; a reload with the upstream changed to
#      :18082 updates the routes; the backend that then opens on :18082 carries
#      behind=nginx:<pid>:/ on its OPENED. In the efficiency step the connect hook must not
#      run for the 10 000 non-proxy connections, and must run for requests through nginx.
# Self-contained: it builds its own binaries, runs its own nats-server on a private port
# and store, runs its agent with its own spool directory, stops the portwarden-agent
# systemd unit while it runs (it would share the BPF programs' run counters) and puts
# everything back on exit.
set -euo pipefail
cd "$(dirname "$0")/.."

NATS_PORT=4333
SERVER_PORT=8099
UDP_PORT=8098
RESTART_PORT=8097
NETNS_PORT=8096
SPOOL_PORT=8095
MARKER_PORT=8094
EXPOSURE_PORT=8093
DOCKER_HOST_PORT=18090
PROXY_PORT=8080
BACKEND_PORT=18081
BACKEND2_PORT=18082
PROXY_UNIT=pw-e2e-nginx
PROXY_WINDOW_S=10
DOCKER_IMAGE=busybox:1.36
DOCKER_NAME=pw-e2e
NFT_TABLE=pw_e2e
EXPOSURE_WINDOW_S=5
RESTART_UNIT=pw-e2e
CONNECTIONS=10000
UDP_CLIENTS=1000
MAX_LATENCY_MS=1000
LINE_TIMEOUT_S=5
RESTART_WINDOW_S=3
RECHECK_S=10
REQUIRED_PROGS=(on_listen on_stop on_udp_bind on_udp_unhash on_connect4 on_connect6) # the probes must be among the agent's programs

work=$(mktemp -d)
nats_url="nats://127.0.0.1:$NATS_PORT"
pids=() # background children of this script (not the sudo-run agent)
agent_pid=""
nats_pid=""
unit_was_active=false
old_bpf_stats=""
ssh_service_restore="" # start|stop: undoes the socket-activation check's change to ssh.service
docker_started=false
docker_rule=false

log() { echo "e2e: $*"; }

fail() {
	echo "e2e: FAIL: $*" >&2
	for f in agent nats watch watch-replay; do
		[ -s "$work/$f.log" ] && { echo "--- $f.log (tail) ---" >&2; tail -n 20 "$work/$f.log" >&2; }
	done
	exit 1
}

cleanup() {
	local status=$?
	trap - EXIT
	for p in "${pids[@]}"; do kill "$p" 2>/dev/null || true; done
	if [ -n "$agent_pid" ]; then
		sudo pkill -TERM -f "^$work/portwarden-agent " 2>/dev/null || true
		wait "$agent_pid" 2>/dev/null || true
	fi
	sudo pkill -TERM -f "http.server --bind 127.0.0.1 $NETNS_PORT" 2>/dev/null || true
	sudo systemctl stop "$RESTART_UNIT" 2>/dev/null || true
	sudo systemctl stop "$PROXY_UNIT" 2>/dev/null || true
	sudo nft delete table inet "$NFT_TABLE" 2>/dev/null || true
	$docker_rule && sudo iptables -D DOCKER-USER -p tcp --dport 80 -j DROP 2>/dev/null || true
	$docker_started && sudo docker rm -f "$DOCKER_NAME" >/dev/null 2>&1 || true
	for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done
	[ -n "$ssh_service_restore" ] && sudo systemctl -q "$ssh_service_restore" ssh.service || true
	[ -n "$old_bpf_stats" ] && sudo sysctl -q kernel.bpf_stats_enabled="$old_bpf_stats" || true
	$unit_was_active && sudo systemctl start portwarden-agent || true
	sudo rm -rf "$work/spool" # written by the root-run agent
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

# count_in <file> <extended regex>: the number of matching lines.
count_in() { grep -cE -- "$2" "$1" || true; }

# seen_in <file> <extended regex> <count>: the file has at least <count> matching lines.
seen_in() { [ "$(count_in "$1" "$2")" -ge "$3" ]; }

# seen <extended regex> <count>: the watch output has at least <count> matching lines.
seen() { seen_in "$work/watch.log" "$1" "$2"; }

# agent_prog_ids: ids of every BPF program the agent holds (through a prog or link fd),
# read from its /proc/<pid>/fdinfo; bpftool's own "pids" field is empty here because the
# agent closes the prog fds once the links are attached. Anything the agent attaches
# later or renames is picked up without editing this script.
agent_prog_ids() {
	local pid
	pid=$(pgrep -f "^$work/portwarden-agent ") || fail "portwarden-agent process not found"
	sudo sh -c "cat /proc/$pid/fdinfo/* 2>/dev/null" | awk '/^prog_id:/ {print $2}' | sort -un
}

# agent_runs: "<name> <run_cnt> <run_time_ns>" for each program id in $prog_ids.
agent_runs() {
	sudo bpftool prog show -j | jq -r --arg ids "$prog_ids" \
		'($ids | split("\n") | map(tonumber)) as $want | .[] | select(.id as $i | $want | index($i)) | "\(.name) \(.run_cnt // 0) \(.run_time_ns // 0)"' | sort
}

# run_delta <runs before> <runs after> <prog>: "<run_cnt delta> <run_time_ns delta>".
run_delta() {
	awk -v p="$3" 'NR == FNR { if ($1 == p) { r = $2; n = $3 } next } $1 == p { print $2 - r, $3 - n }' \
		<(echo "$1") <(echo "$2")
}

# print_deltas <runs before> <runs after>: one "run_cnt +N" line per program.
print_deltas() {
	local name runs
	for name in $(awk '{print $1}' <<<"$2"); do
		read -r runs _ < <(run_delta "$1" "$2" "$name")
		[ -n "$runs" ] || fail "no run counts for $name"
		log "  $name run_cnt +$runs"
	done
}

# check_udp_prog <runs before> <runs after> <prog>: the program ran at least once per
# UDP client socket; prints its average ns per run.
check_udp_prog() {
	local runs ns
	read -r runs ns < <(run_delta "$1" "$2" "$3")
	[ -n "$runs" ] || fail "no run counts for $3"
	[ "$runs" -ge "$UDP_CLIENTS" ] || fail "$3 ran $runs times for $UDP_CLIENTS UDP client sockets"
	echo "$3 average ns per run: $((ns / runs)) ($runs runs)"
}

# line_ns <watch line>: the line's timestamp in ns since the epoch.
line_ns() { date -d "${1%% *}" +%s%N; }

start_server() {
	python3 -m http.server "$SERVER_PORT" --bind 0.0.0.0 --directory "$work/www" >/dev/null 2>&1 &
	server_pid=$!
	pids+=("$server_pid")
}

stop_server() {
	kill "$server_pid"
	wait "$server_pid" 2>/dev/null || true
}

start_nats() {
	nats-server -js -a 127.0.0.1 -p "$NATS_PORT" -sd "$work/js" >>"$work/nats.log" 2>&1 &
	nats_pid=$!
	pids+=("$nats_pid")
	wait_for "nats-server" 10 bash -c "exec 3<>/dev/tcp/127.0.0.1/$NATS_PORT" 2>/dev/null
}

start_agent() {
	sudo "$work/portwarden-agent" --nats-url "$nats_url" --heartbeat 1s --recheck "${RECHECK_S}s" \
		--spool-dir "$work/spool" >>"$work/agent.log" 2>&1 &
	agent_pid=$!
}

stop_agent() {
	# Anchored on the binary path, so it matches the agent and not its sudo wrapper.
	sudo pkill -TERM -f "^$work/portwarden-agent " || fail "no portwarden-agent process to stop"
	wait "$agent_pid" || fail "portwarden-agent exited non-zero on SIGTERM"
	agent_pid=""
}

agent_alive() { kill -0 "$agent_pid" 2>/dev/null || fail "portwarden-agent exited early"; }
stream_ready() { agent_alive; nats --server "$nats_url" stream info ASM_EVENTS >/dev/null 2>&1; }

# hold_udp <port>: binds a UDP socket to 0.0.0.0:<port> in the background and holds it.
hold_udp() {
	python3 -c 'import signal, socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", int(sys.argv[1])))
signal.pause()' "$1" &
	pids+=($!)
}

for port in "$SERVER_PORT" "$RESTART_PORT" "$NETNS_PORT" "$SPOOL_PORT" "$EXPOSURE_PORT" "$DOCKER_HOST_PORT" \
	"$PROXY_PORT" "$BACKEND_PORT" "$BACKEND2_PORT"; do
	ss -Hltn "sport = :$port" | grep -q . && fail "tcp port $port is already in use"
done
for port in "$UDP_PORT" "$MARKER_PORT"; do
	ss -Hlun "sport = :$port" | grep -q . && fail "udp port $port is already in use"
done
for unit in "$RESTART_UNIT" "$PROXY_UNIT"; do
	systemctl is-active --quiet "$unit" && fail "unit $unit is already running"
	sudo systemctl reset-failed "$unit" 2>/dev/null || true
done
mkdir -p "$work/www"

log "building"
go build -o "$work/portwarden-agent" ./cmd/portwarden-agent
go build -o "$work/portwarden-watch" ./cmd/portwarden-watch

systemctl is-active --quiet portwarden-agent && unit_was_active=true
$unit_was_active && sudo systemctl stop portwarden-agent

start_nats
start_agent
wait_for "stream ASM_EVENTS" 15 stream_ready

"$work/portwarden-watch" --nats-url "$nats_url" --since 0s >"$work/watch.log" 2>&1 &
pids+=($!)
# A heartbeat arriving proves the consumer is live before any listener is opened.
wait_for "first heartbeat in portwarden-watch" 10 seen HEARTBEAT 1

log "latency: listen on :$SERVER_PORT"
t0=$(now_ns)
start_server
wait_for "OPENED tcp 0.0.0.0:$SERVER_PORT" "$LINE_TIMEOUT_S" seen "OPENED tcp 0.0.0.0:$SERVER_PORT " 1
t1=$(now_ns)
latency_ms=$(((t1 - t0) / 1000000))
echo "opened latency: $latency_ms ms"

stop_server
wait_for "CLOSED tcp 0.0.0.0:$SERVER_PORT" "$LINE_TIMEOUT_S" seen "CLOSED tcp 0.0.0.0:$SERVER_PORT " 1
log "closed line seen"

[ "$latency_ms" -le "$MAX_LATENCY_MS" ] || fail "opened latency $latency_ms ms > $MAX_LATENCY_MS ms"

log "latency: UDP bind on :$UDP_PORT"
t0=$(now_ns)
hold_udp "$UDP_PORT"
udp_pid=$!
wait_for "OPENED udp 0.0.0.0:$UDP_PORT" "$LINE_TIMEOUT_S" seen "OPENED udp 0.0.0.0:$UDP_PORT " 1
t1=$(now_ns)
udp_latency_ms=$(((t1 - t0) / 1000000))
echo "udp opened latency: $udp_latency_ms ms"
kill "$udp_pid"
wait "$udp_pid" 2>/dev/null || true
wait_for "CLOSED udp 0.0.0.0:$UDP_PORT" "$LINE_TIMEOUT_S" seen "CLOSED udp 0.0.0.0:$UDP_PORT " 1
[ "$udp_latency_ms" -le "$MAX_LATENCY_MS" ] || fail "udp opened latency $udp_latency_ms ms > $MAX_LATENCY_MS ms"

log "restart: transient unit $RESTART_UNIT on :$RESTART_PORT"
sudo systemd-run --quiet --unit "$RESTART_UNIT" -p Restart=no \
	python3 -m http.server "$RESTART_PORT" --directory "$work/www"
wait_for "OPENED tcp 0.0.0.0:$RESTART_PORT" "$LINE_TIMEOUT_S" \
	seen "OPENED tcp 0.0.0.0:$RESTART_PORT .* unit=$RESTART_UNIT.service" 1
restart_at=$(now_ns)
sudo systemctl restart "$RESTART_UNIT"
wait_for "OWNER_CHANGED tcp 0.0.0.0:$RESTART_PORT" "$RESTART_WINDOW_S" \
	seen "OWNER_CHANGED tcp 0.0.0.0:$RESTART_PORT .* unit=$RESTART_UNIT.service" 1
# A CLOSED would come when the 2 s close grace ends, so the whole window is waited out.
until [ "$(now_ns)" -ge $((restart_at + RESTART_WINDOW_S * 1000000000)) ]; do sleep 0.1; done
owner_changes=$(count_in "$work/watch.log" "OWNER_CHANGED tcp 0.0.0.0:$RESTART_PORT ")
[ "$owner_changes" -eq 1 ] || fail "expected one OWNER_CHANGED for :$RESTART_PORT, got $owner_changes"
! seen "CLOSED tcp 0.0.0.0:$RESTART_PORT " 1 || fail "restarting $RESTART_UNIT produced a CLOSED for :$RESTART_PORT"
echo "OWNER_CHANGED seen for :$RESTART_PORT, no CLOSED within ${RESTART_WINDOW_S}s"
sudo systemctl stop "$RESTART_UNIT"

log "container netns: listener on 127.0.0.1:$NETNS_PORT in a fresh netns"
host_netns=$(readlink /proc/self/ns/net | tr -dc 0-9)
sudo unshare -n sh -c "ip link set lo up; exec python3 -m http.server --bind 127.0.0.1 $NETNS_PORT --directory $work/www" \
	>/dev/null 2>&1 &
pids+=($!)
wait_for "OPENED tcp 127.0.0.1:$NETNS_PORT" "$LINE_TIMEOUT_S" seen "OPENED tcp 127.0.0.1:$NETNS_PORT " 1
netns_line=$(grep -m1 -- "OPENED tcp 127.0.0.1:$NETNS_PORT " "$work/watch.log")
listener_netns=$(grep -oE ' netns=[0-9]+' <<<"$netns_line" | tr -dc 0-9) || true
[ -n "$listener_netns" ] && [ "$listener_netns" != "$host_netns" ] ||
	fail "netns listener line has no foreign netns= (host $host_netns): $netns_line"
echo "netns listener: netns=$listener_netns (host $host_netns)"
sudo pkill -TERM -f "http.server --bind 127.0.0.1 $NETNS_PORT"

log "exposure: :$EXPOSURE_PORT behind an nft drop, then an accept"
# firewall_reads: how many firewall-triggered views the agent has read so far.
firewall_reads() { count_in "$work/agent.log" '"msg":"firewall read","trigger":"firewall"'; }
sudo nft delete table inet "$NFT_TABLE" 2>/dev/null || true
reads_before=$(firewall_reads)
sudo nft -f - <<NFT
table inet $NFT_TABLE {
	chain input {
		type filter hook input priority 10; policy accept;
		tcp dport $EXPOSURE_PORT drop
	}
}
NFT
# The listener opens after the agent has read the drop rule, so its first level is bound.
read_since() { [ "$(firewall_reads)" -gt "$reads_before" ]; }
wait_for "the agent to read the drop rule" "$EXPOSURE_WINDOW_S" read_since
python3 -m http.server "$EXPOSURE_PORT" --bind 0.0.0.0 --directory "$work/www" >/dev/null 2>&1 &
exposure_pid=$!
pids+=("$exposure_pid")
wait_for "EXPOSURE tcp 0.0.0.0:$EXPOSURE_PORT new->bound" "$LINE_TIMEOUT_S" \
	seen "EXPOSURE tcp 0.0.0.0:$EXPOSURE_PORT new->bound trigger=opened .*nft: drop tcp/$EXPOSURE_PORT from 0/0" 1
t0=$(now_ns)
sudo nft insert rule inet "$NFT_TABLE" input tcp dport "$EXPOSURE_PORT" accept
wait_for "EXPOSURE tcp 0.0.0.0:$EXPOSURE_PORT bound->host_firewall_open" "$EXPOSURE_WINDOW_S" \
	seen "EXPOSURE tcp 0.0.0.0:$EXPOSURE_PORT bound->host_firewall_open trigger=firewall .*nft: accept tcp/$EXPOSURE_PORT from 0/0" 1
t1=$(now_ns)
echo "exposure firewall latency: $(((t1 - t0) / 1000000)) ms ($(grep -m1 -- "EXPOSURE tcp 0.0.0.0:$EXPOSURE_PORT bound->" "$work/watch.log" | cut -d' ' -f4-))"
kill "$exposure_pid"
wait "$exposure_pid" 2>/dev/null || true
sudo nft delete table inet "$NFT_TABLE"

log "docker: container listener behind -p $DOCKER_HOST_PORT:80"
if ! command -v docker >/dev/null || ! sudo docker info >/dev/null 2>&1; then
	echo "docker exposure: SKIP (docker unavailable)"
elif ! sudo docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1 && ! sudo docker pull -q "$DOCKER_IMAGE" >/dev/null 2>&1; then
	echo "docker exposure: SKIP (image $DOCKER_IMAGE unavailable)"
else
	sudo docker rm -f "$DOCKER_NAME" >/dev/null 2>&1 || true
	docker_started=true
	sudo docker run -d --name "$DOCKER_NAME" -p "$DOCKER_HOST_PORT:80" "$DOCKER_IMAGE" httpd -f -p 80 >/dev/null
	ctr_pid=$(sudo docker inspect -f '{{.State.Pid}}' "$DOCKER_NAME")
	ctr_netns=$(sudo readlink "/proc/$ctr_pid/ns/net" | tr -dc 0-9)
	# busybox httpd may bind 0.0.0.0:80 or [::]:80.
	ctr_open="EXPOSURE tcp (0\.0\.0\.0|\[::\]):80 [a-z_]+->host_firewall_open trigger=[a-z]+ netns=$ctr_netns .*tcp/$DOCKER_HOST_PORT "
	wait_for "container :80 at host_firewall_open" 10 seen "$ctr_open" 1
	echo "docker exposure: $(grep -m1 -E -- "$ctr_open" "$work/watch.log" | cut -d' ' -f4-)"
	docker_rule=true
	sudo iptables -I DOCKER-USER -p tcp --dport 80 -j DROP
	wait_for "container :80 back to bound" "$EXPOSURE_WINDOW_S" \
		seen "EXPOSURE tcp (0\.0\.0\.0|\[::\]):80 host_firewall_open->bound trigger=firewall netns=$ctr_netns " 1
	sudo iptables -D DOCKER-USER -p tcp --dport 80 -j DROP
	docker_rule=false
	wait_for "container :80 open again" "$EXPOSURE_WINDOW_S" seen "$ctr_open" 2
	echo "docker exposure follows the host firewall: open -> bound (DOCKER-USER drop) -> open"
	sudo docker rm -f "$DOCKER_NAME" >/dev/null
	docker_started=false
fi

log "proxy: nginx ($PROXY_UNIT) on :$PROXY_PORT -> 127.0.0.1:$BACKEND_PORT"
command -v nginx >/dev/null || fail "nginx is not installed (apt-get install nginx)"
# backend <port>: a python http.server on 127.0.0.1:<port>.
backend() {
	python3 -m http.server "$1" --bind 127.0.0.1 --directory "$work/www" >/dev/null 2>&1 &
	pids+=($!)
}
# nginx_conf <backend port>: the e2e nginx's whole config.
nginx_conf() {
	mkdir -p "$work/nginx"
	cat >"$work/nginx/nginx.conf" <<NGINX
pid $work/nginx/nginx.pid;
error_log $work/nginx/error.log;
events {}
http {
	access_log off;
	upstream app {
		server 127.0.0.1:$1;
	}
	server {
		listen $PROXY_PORT;
		location / {
			proxy_pass http://app;
		}
	}
}
NGINX
}
backend "$BACKEND_PORT"
wait_for "OPENED tcp 127.0.0.1:$BACKEND_PORT" "$LINE_TIMEOUT_S" seen "OPENED tcp 127.0.0.1:$BACKEND_PORT " 1
nginx_conf "$BACKEND_PORT"
sudo systemd-run --quiet --unit "$PROXY_UNIT" -p Restart=no /usr/sbin/nginx -c "$work/nginx/nginx.conf" -g "daemon off;"
# route_to <trigger> <backend port> <backend suffix regex>: a PROXY line with that trigger
# whose :8080 / route ends at the backend.
route_to() { echo "PROXY nginx pid=[0-9]+ \\S+ trigger=$1 routes=[0-9]+ .*\\| \\*:$PROXY_PORT / proxy -> 127\\.0\\.0\\.1:$2 $3"; }
config_line=$(route_to started "$BACKEND_PORT" "pid=[0-9]+ \\S*python3\\S* \\[config\\]")
wait_for "proxy.routes naming the backend [config]" "$PROXY_WINDOW_S" seen "$config_line" 1
echo "proxy routes: $(grep -m1 -E -- "$config_line" "$work/watch.log" | cut -d' ' -f4-)"
nginx_master=$(grep -m1 -E -- "$config_line" "$work/watch.log" | grep -oE 'PROXY nginx pid=[0-9]+' | tr -dc 0-9)
codes=$(curl -s -o /dev/null -w '%{http_code}\n' --max-time 30 "http://127.0.0.1:$PROXY_PORT/?[1-20]" | sort | uniq -c)
[ "$(awk '{print $2}' <<<"$codes")" = "200" ] || fail "requests through nginx: $codes"
seen_line=$(route_to traffic "$BACKEND_PORT" "pid=[0-9]+ \\S*python3\\S* \\[config,seen\\]")
wait_for "the backend seen in traffic" "$PROXY_WINDOW_S" seen "$seen_line" 1
echo "proxy traffic: $(grep -m1 -E -- "$seen_line" "$work/watch.log" | cut -d' ' -f4-)"
# Reload with the upstream moved to a port nothing listens on yet.
nginx_conf "$BACKEND2_PORT"
t0=$(now_ns)
sudo /usr/sbin/nginx -c "$work/nginx/nginx.conf" -s reload
reload_line=$(route_to config "$BACKEND2_PORT" "\\[config\\] \\(no listener\\)")
wait_for "proxy.routes after the reload" "$PROXY_WINDOW_S" seen "$reload_line" 1
echo "proxy reload: $(((($(now_ns) - t0)) / 1000000)) ms ($(grep -m1 -E -- "$reload_line" "$work/watch.log" | cut -d' ' -f4-))"
backend "$BACKEND2_PORT"
behind_line="OPENED tcp 127\\.0\\.0\\.1:$BACKEND2_PORT .* behind=nginx:$nginx_master:/\\[config\\]"
wait_for "the new backend's OPENED behind nginx" "$LINE_TIMEOUT_S" seen "$behind_line" 1
echo "behind_proxy: $(grep -m1 -E -- "$behind_line" "$work/watch.log" | cut -d' ' -f4-)"
joined_line=$(route_to listener "$BACKEND2_PORT" "pid=[0-9]+ \\S*python3\\S* \\[config\\]")
wait_for "proxy.routes joined to the new backend" "$LINE_TIMEOUT_S" seen "$joined_line" 1

log "socket activation: :22 after a recheck"
if ! systemctl is-active --quiet ssh.socket; then
	echo "socket activation: SKIP (ssh.socket is not active)"
else
	# The baseline already holds :22 with its units; changing its holders (sshd joins
	# systemd, or leaves) makes the next recheck report it as an OWNER_CHANGED.
	# The restore action is set before each change, so an interrupted change is undone too.
	if systemctl is-active --quiet ssh.service; then
		ssh_service_restore=start
		sudo systemctl -q stop ssh.service
	else
		ssh_service_restore=stop
		# A connection activates ssh.service, whose sshd inherits the listening sockets.
		timeout 5 bash -c "exec 3<>/dev/tcp/127.0.0.1/22; head -c 4 <&3" >/dev/null ||
			fail "connecting to :22 did not get an SSH banner"
		wait_for "ssh.service to start" 10 systemctl is-active --quiet ssh.service
	fi
	ssh_pattern=" tcp 0.0.0.0:22 pid=1 .* unit=ssh.service sock=ssh.socket"
	wait_for ":22 with unit=ssh.service sock=ssh.socket" $((RECHECK_S * 3)) seen "$ssh_pattern" 1
	echo "socket activation: $(grep -m1 -E -- "$ssh_pattern" "$work/watch.log" | cut -d' ' -f4-)"
fi

log "efficiency: $CONNECTIONS connections with bpf stats on"
old_bpf_stats=$(sysctl -n kernel.bpf_stats_enabled)
sudo sysctl -q kernel.bpf_stats_enabled=1
prog_ids=$(agent_prog_ids)
runs_start=$(agent_runs)
for want in "${REQUIRED_PROGS[@]}"; do
	grep -q "^$want " <<<"$runs_start" || fail "agent does not hold BPF program $want (holds: $(awk '{print $1}' <<<"$runs_start" | tr '\n' ' '))"
done
log "agent BPF programs: $(awk '{print $1}' <<<"$runs_start" | tr '\n' ' ')"

start_server
wait_for "second OPENED tcp 0.0.0.0:$SERVER_PORT" "$LINE_TIMEOUT_S" seen "OPENED tcp 0.0.0.0:$SERVER_PORT " 2
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

print_deltas "$runs_before" "$runs_after"
read -r c4 _ < <(run_delta "$runs_before" "$runs_after" on_connect4)
read -r c6 _ < <(run_delta "$runs_before" "$runs_after" on_connect6)
echo "connect hook runs for $CONNECTIONS non-proxy connections: $((c4 + c6))"
[ "$((c4 + c6))" -eq 0 ] || fail "the proxy connect hook ran $((c4 + c6)) times for non-proxy connections"
# Control: requests through nginx run it (one upstream connect per request).
proxy_runs_before=$(agent_runs)
curl -s -o /dev/null --max-time 30 "http://127.0.0.1:$PROXY_PORT/?[1-50]"
proxy_runs_after=$(agent_runs)
read -r c4 _ < <(run_delta "$proxy_runs_before" "$proxy_runs_after" on_connect4)
[ "$c4" -ge 50 ] || fail "connect hook control: on_connect4 ran $c4 times for 50 requests through nginx"
echo "connect hook runs for 50 requests through nginx: $c4"
# Only the TCP probes count: background UDP (resolved, NTP) may run the UDP hooks meanwhile.
read -r listen_runs _ < <(run_delta "$runs_before" "$runs_after" on_listen)
read -r stop_runs _ < <(run_delta "$runs_before" "$runs_after" on_stop)
[ -n "$listen_runs" ] && [ -n "$stop_runs" ] || fail "no run counts for on_listen/on_stop"
tcp_runs=$((listen_runs + stop_runs))
echo "bpf runs during load: $tcp_runs (on_listen + on_stop)"
[ "$tcp_runs" -eq 0 ] || fail "on_listen/on_stop ran $tcp_runs times during the connection load"

log "efficiency: $UDP_CLIENTS UDP client sockets"
udp_events_before=$(count_in "$work/watch.log" " (OPENED|CLOSED) udp ")
runs_before=$(agent_runs)
python3 -c 'import socket, sys
for _ in range(int(sys.argv[1])):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(b"x", ("127.0.0.1", 9))
    s.close()' "$UDP_CLIENTS"
runs_after=$(agent_runs)
# The marker is bound after the clients closed; the stream is ordered, so once its OPENED
# is in, any event the clients caused is in too.
hold_udp "$MARKER_PORT"
marker_pid=$!
wait_for "OPENED udp 0.0.0.0:$MARKER_PORT" "$LINE_TIMEOUT_S" seen "OPENED udp 0.0.0.0:$MARKER_PORT " 1
udp_events_after=$(count_in "$work/watch.log" " (OPENED|CLOSED) udp ")
kill "$marker_pid"
wait "$marker_pid" 2>/dev/null || true
print_deltas "$runs_before" "$runs_after"
check_udp_prog "$runs_before" "$runs_after" on_udp_bind
check_udp_prog "$runs_before" "$runs_after" on_udp_unhash
[ "$udp_events_after" -eq $((udp_events_before + 1)) ] ||
	fail "UDP client sockets produced $((udp_events_after - udp_events_before - 1)) UDP events"
echo "udp client sockets: no UDP events"

log "spool: :$SPOOL_PORT opened while nats-server is down, across an agent restart"
kill "$nats_pid"
wait "$nats_pid" 2>/dev/null || true
python3 -m http.server "$SPOOL_PORT" --bind 0.0.0.0 --directory "$work/www" >/dev/null 2>&1 &
pids+=($!)
# The record's listener key ("<netns>/tcp/0.0.0.0:8095") is stored verbatim in the segment.
spool_has_listener() { sudo grep -rqa -- "/tcp/0.0.0.0:$SPOOL_PORT" "$work/spool"; }
wait_for ":$SPOOL_PORT OPENED in the spool" "$LINE_TIMEOUT_S" spool_has_listener
agent_stopped_at=$(now_ns)
stop_agent
start_agent
start_nats
"$work/portwarden-watch" --nats-url "$nats_url" --since 5m >"$work/watch-replay.log" 2>&1 &
pids+=($!)
wait_for "replayed OPENED tcp 0.0.0.0:$SPOOL_PORT" 30 \
	seen_in "$work/watch-replay.log" "OPENED tcp 0.0.0.0:$SPOOL_PORT " 1
spool_line=$(grep -m1 -- "OPENED tcp 0.0.0.0:$SPOOL_PORT " "$work/watch-replay.log")
[ "$(line_ns "$spool_line")" -lt "$agent_stopped_at" ] ||
	fail "spooled OPENED does not carry its original time: $spool_line"
echo "spool: replayed $(cut -d' ' -f1,4- <<<"$spool_line")"

! grep -q '^GAP ' "$work/watch.log" "$work/watch-replay.log" || fail "portwarden-watch reported a GAP"
log "ok"
