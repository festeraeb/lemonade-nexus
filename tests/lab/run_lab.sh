#!/bin/bash
# Real-path lab: a client and a server of the mesh in two network
# namespaces joined by a veth pair, with nftables and netem applied inside
# the client namespace only. Touches nothing outside its own namespaces.
#
#   sudo tests/lab/run_lab.sh <transport_lab binary> <out dir> <scenario...>
# Scenarios: clean udp-drop tcp443-only netem mtu1400 swap soak restart
set -u
LAB=$1; OUT=$2; shift 2
NC=nxlab-c; NS=nxlab-s
mkdir -p "$OUT"

setup() {
    ip netns add $NC; ip netns add $NS
    ip link add nxc0 type veth peer name nxs0
    ip link set nxc0 netns $NC; ip link set nxs0 netns $NS
    ip -n $NC addr add 10.99.0.1/24 dev nxc0; ip -n $NS addr add 10.99.0.2/24 dev nxs0
    ip -n $NC link set lo up; ip -n $NS link set lo up
    ip -n $NC link set nxc0 up; ip -n $NS link set nxs0 up
}
teardown() {
    pkill -f "transport_lab (server|client) --dir $OUT" 2>/dev/null
    sleep 0.5
    ip netns del $NC 2>/dev/null; ip netns del $NS 2>/dev/null
}
udp_drop_on() {
    ip netns exec $NC nft -f - <<'NFT'
table inet nxlab {
  chain out { type filter hook output priority 0; oifname "lo" accept; meta l4proto udp drop; }
  chain in  { type filter hook input  priority 0; iifname "lo" accept; meta l4proto udp drop; }
}
NFT
}
udp_drop_off() { ip netns exec $NC nft delete table inet nxlab 2>/dev/null; }
tcp443_only() {
    ip netns exec $NC nft -f - <<'NFT'
table inet nxlab {
  chain out { type filter hook output priority 0; policy drop;
    oifname "lo" accept; ct state established,related accept; tcp dport 443 accept; }
  chain in  { type filter hook input priority 0; policy drop;
    iifname "lo" accept; ct state established,related accept; }
}
NFT
}
start_server() {  # $1 = scenario dir
    ip netns exec $NS "$LAB" server --dir "$1" --server-ip 10.99.0.2 --udp-port 51940 --wss-port 443 "${SERVER_ARGS[@]}" \
        >> "$1/server.log" 2>&1 &
    SERVER_PID=$!
    for i in $(seq 100); do grep -q server_ready "$1/server.log" 2>/dev/null && return 0; sleep 0.1; done
    echo "server did not start" >&2; return 1
}
run_client() {  # $1 = dir, rest = client args
    local d=$1; shift
    ip netns exec $NC "$LAB" client --dir "$d" --server-ip 10.99.0.2 --udp-port 51940 --wss-port 443 "$@" \
        > "$d/client.jsonl" 2> "$d/client.err"
}

for sc in "$@"; do
    SERVER_ARGS=()
    [ "$sc" = storm ] && SERVER_ARGS=(--bridge-per-ip 1000 --bridge-idle 5)
    D="$OUT/$sc"; rm -rf "$D"; mkdir -p "$D"
    teardown; setup
    case $sc in
      udp-drop)    udp_drop_on ;;
      tcp443-only) tcp443_only ;;
      netem)       ip netns exec $NC tc qdisc add dev nxc0 root netem delay 80ms loss 2% ;;
      netem-wss)   ip netns exec $NC tc qdisc add dev nxc0 root netem delay 80ms loss 2%; tcp443_only ;;
      mtu1400)     ip -n $NC link set nxc0 mtu 1400; ip -n $NS link set nxs0 mtu 1400 ;;
    esac
    start_server "$D" || { teardown; continue; }
    case $sc in
      swap)
        # Cut UDP twice during a 40 s stream.
        run_client "$D" --stream-sec 40 --upload-mib 0 &
        CPID=$!
        sleep 10; echo "cut $(date +%s.%N)" >> "$D/events"; udp_drop_on
        sleep 8;  echo "restore $(date +%s.%N)" >> "$D/events"; udp_drop_off
        sleep 8;  echo "cut $(date +%s.%N)" >> "$D/events"; udp_drop_on
        sleep 6;  echo "restore $(date +%s.%N)" >> "$D/events"; udp_drop_off
        wait $CPID ;;
      soak)
        DUR=${SOAK_SEC:-1800}
        run_client "$D" --stream-sec 0 --upload-mib 0 --soak-sec "$DUR" &
        CPID=$!
        END=$(( $(date +%s) + DUR ))
        while kill -0 $CPID 2>/dev/null && [ "$(date +%s)" -lt "$END" ]; do
            sleep $(( 20 + RANDOM % 21 )); echo "cut $(date +%s)" >> "$D/events"; udp_drop_on
            sleep $(( 5 + RANDOM % 11 ));  echo "restore $(date +%s)" >> "$D/events"; udp_drop_off
        done
        wait $CPID ;;
      storm)
        SPID=$(pgrep -f "transport_lab server --dir $D" | head -1)
        snap() { echo "{\"event\":\"server_res\",\"at\":\"$1\",\"fds\":$(ls /proc/$SPID/fd | wc -l),\"rss_kb\":$(awk '/VmRSS/{print $2}' /proc/$SPID/status),\"threads\":$(awk '/Threads/{print $2}' /proc/$SPID/status)}" >> "$D/server_res.jsonl"; }
        snap before
        ip netns exec $NC "$LAB" storm --url wss://10.99.0.2:443/api/transport/ws/dataplane --ca "$D/cert.pem" \
            --clients 200 --rounds 5 > "$D/client.jsonl" 2> "$D/client.err"
        sleep 8; snap after_storm
        ip netns exec $NC "$LAB" abuse --host 10.99.0.2 --port 443 --url wss://10.99.0.2:443/api/transport/ws/dataplane \
            --ca "$D/cert.pem" --silent 20 --garbage 200 --hold-sec 10 >> "$D/client.jsonl" 2>> "$D/client.err"
        snap after_abuse
        sleep 15; snap settled
        ip netns exec $NC curl -s --cacert "$D/cert.pem" https://10.99.0.2/api/health >> "$D/client.jsonl"; echo >> "$D/client.jsonl"
        kill -0 $SPID && echo '{"event":"server_alive"}' >> "$D/client.jsonl" ;;
      capture-udp|capture-wss)
        # Record the server link while a stream and an upload cross it, then
        # look for the plaintext (the upload body is 'u' repeated).
        [ "$sc" = capture-wss ] && udp_drop_on
        ip netns exec $NS tcpdump -i nxs0 -s 0 -w "$D/link.pcap" -U 2>/dev/null &
        TPID=$!; sleep 1
        run_client "$D" --stream-sec 5 --upload-mib 4
        sleep 1; kill $TPID; wait $TPID 2>/dev/null
        echo "{\"event\":\"capture\",\"bytes\":$(stat -c %s "$D/link.pcap"),\"plaintext_upload_runs\":$(grep -c -a 'uuuuuuuuuuuuuuuuuuuuuuuuuuuuuuuu' "$D/link.pcap"),\"plaintext_stream\":$(grep -c -a 'data: [0-9]' "$D/link.pcap"),\"plaintext_pong\":$(grep -c -a 'pong' "$D/link.pcap")}" >> "$D/client.jsonl"
        rm -f "$D/link.pcap" ;;
      ipchange)
        # The client's address changes mid-stream (Wi-Fi to cellular): the
        # old address goes away and a new one comes up; the client process
        # gets no notice. A /ping every 100 ms shows the outage.
        # Keep the new address when the old primary goes (Linux removes
        # secondaries with their primary otherwise).
        ip netns exec $NC sysctl -qw net.ipv4.conf.nxc0.promote_secondaries=1
        run_client "$D" --stream-sec 0 --upload-mib 0 --ping-watch-sec 40 &
        CPID=$!
        sleep 12; echo "ipchange $(date +%s.%N)" >> "$D/events"
        ip -n $NC addr add 10.99.0.11/24 dev nxc0; ip -n $NC addr del 10.99.0.1/24 dev nxc0
        sleep 10; echo "ipchange-under-udp-block $(date +%s.%N)" >> "$D/events"
        udp_drop_on; ip -n $NC addr add 10.99.0.21/24 dev nxc0; ip -n $NC addr del 10.99.0.11/24 dev nxc0
        wait $CPID ;;
      restart)
        # The server process restarts (same keys) while the client pings it
        # every 100 ms; the client process keeps running.
        run_client "$D" --stream-sec 0 --upload-mib 0 --ping-watch-sec 45 &
        CPID=$!
        sleep 15; echo "kill $(date +%s.%N)" >> "$D/events"; kill $SERVER_PID; wait $SERVER_PID 2>/dev/null
        sleep 3;  echo "start $(date +%s.%N)" >> "$D/events"; start_server "$D"
        wait $CPID ;;
      *)
        run_client "$D" --stream-sec 15 --upload-mib 8 ;;
    esac
    echo "$sc client exit $?" >> "$OUT/summary"
    teardown
done
chown -R "${SUDO_UID:-0}:${SUDO_GID:-0}" "$OUT"
