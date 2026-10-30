#!/usr/bin/env bash
# N-process development mesh under OPERATOR TRUST (fork-local; see docs/Operator-Trust.md).
#
# Same shape as scripts/dev-mesh.sh (node 0 is the mesh root and the pinned
# genesis anchor; every node is an enrolled server on localhost with real UDP
# transport), with the operator-trust additions: one operator root keypair, the
# root public key pinned in every config as operator_root_pubkey, and one
# operator-signed enrollment per node in its attestation cache. The binary MUST
# be a LEMONADE_NEXUS_OPERATOR_TRUST=ON build; a default build refuses the
# profile and this check then fails, which is the correct answer for it.
#
# What a PASS means: N processes founded Epoch 1 on hosts with no SEV-SNP, TDX
# or TPM, because the operator vouched for each of them. It is NOT a hardware
# attestation result.
#
# Usage:
#   scripts/operator-mesh.sh [start|check|stop|run]   (default: run)
# Env:
#   BIN    server binary (default: build-operator/projects/LemonadeNexus/lemonade-nexus)
#   WORK   working directory (default: /tmp/nexus-operator-mesh)
#   FOUNDERS  founder count, >= 5 (default: 5). Processes = FOUNDERS + 1: n0 is
#             the genesis anchor, which admits peers and never founds itself.
#   WAIT   seconds to observe (default: 90)
set -u
BIN="${BIN:-build-operator/projects/LemonadeNexus/lemonade-nexus}"
WORK="${WORK:-/tmp/nexus-operator-mesh}"
FOUNDERS="${FOUNDERS:-5}"
NODES=$((FOUNDERS + 1))
WAIT="${WAIT:-90}"
MODE="${1:-run}"

say()  { printf '\033[1m[operator-mesh]\033[0m %s\n' "$*"; }
fail() { printf '\033[31m[operator-mesh] FAIL:\033[0m %s\n' "$*"; FAILURES=$((FAILURES+1)); }
gossip_port() { echo $((9410 + $1)); }

provision() {
    rm -rf "$WORK"
    mkdir -p "$WORK"
    declare -a GOSSIP
    ROOT_HEX=""
    for i in $(seq 0 $((NODES-1))); do
        mkdir -p "$WORK/n$i"
        out=$("$BIN" --first-run --data-root "$WORK/n$i" 2>&1)
        idhex=$(echo "$out" | sed -n 's/^Identity pubkey:  *\([0-9a-f]*\).*/\1/p')
        gb64=$(echo "$out" | sed -n 's/^Gossip pubkey:    *\([A-Za-z0-9+/=]*\).*/\1/p')
        if [ -z "$gb64" ]; then
            echo "$out"; say "first-run of n$i produced no gossip pubkey"; exit 1
        fi
        GOSSIP[$i]="$gb64"
        [ "$i" -eq 0 ] && ROOT_HEX="$idhex"
    done
    say "root identity: $ROOT_HEX"
    say "genesis anchor (n0 gossip key): ${GOSSIP[0]}"

    # The operator root key. Lives in WORK for a disposable mesh; on a real
    # network it stays off the servers.
    "$BIN" --operator-keygen "$WORK/operator-root.json" >"$WORK/operator-keygen.log" 2>&1 \
        || { cat "$WORK/operator-keygen.log"; say "operator keygen failed"; exit 1; }
    OPERATOR_B64=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["public_key_b64"])' "$WORK/operator-root.json")
    say "operator root (public): $OPERATOR_B64"

    for i in $(seq 0 $((NODES-1))); do
        "$BIN" --enroll-server "${GOSSIP[$i]}" "mesh-n$i" \
               --data-root "$WORK/n0" --root-pubkey "$ROOT_HEX" \
               --genesis-pubkey "${GOSSIP[0]}" >"$WORK/enroll-n$i.log" 2>&1
        if [ "$i" -ne 0 ]; then
            cp "$WORK/n0/identity/server_cert_mesh-n$i.json" \
               "$WORK/n$i/identity/server_cert.json" || { say "enroll copy failed for n$i"; exit 1; }
        fi
        # The operator signs this server in: its gossip key, this network.
        "$BIN" --operator-enroll "${GOSSIP[$i]}" --operator-keyfile "$WORK/operator-root.json" \
               --genesis-pubkey "${GOSSIP[0]}" --data-root "$WORK/n$i" \
               --operator-enroll-out "$WORK/n$i/security/attestation-cache/operator-enrollment.json" \
               >"$WORK/operator-enroll-n$i.log" 2>&1 \
            || { cat "$WORK/operator-enroll-n$i.log"; say "operator enrollment failed for n$i"; exit 1; }
    done

    RELEASE_B64="${GOSSIP[0]}"
    for i in $(seq 0 $((NODES-1))); do
        seeds='"127.0.0.1:'$(gossip_port 0)'"'
        [ "$i" -eq 0 ] && seeds='"127.0.0.1:'$(gossip_port 1)'"'
        cat > "$WORK/n$i/config.json" <<EOF
{
  "data_root": "$WORK/n$i",
  "bind_address": "127.0.0.1",
  "http_port": $((9210 + i)),
  "private_http_port": $((9260 + i)),
  "udp_port": $((9310 + i)),
  "gossip_port": $(gossip_port "$i"),
  "stun_port": $((9510 + i)),
  "relay_port": $((9610 + i)),
  "dns_port": $((9710 + i)),
  "public_dns_port": $((9710 + i)),
  "mesh_interface": "nexusop$i",
  "log_level": "debug",
  "root_pubkey": "$ROOT_HEX",
  "genesis_pubkey": "${GOSSIP[0]}",
  "release_signing_pubkey": "$RELEASE_B64",
  "operator_root_pubkey": "$OPERATOR_B64",
  "seed_peers": [$seeds],
  "ddns_enabled": false
}
EOF
    done
}

start() {
    for i in $(seq 0 $((NODES-1))); do
        "$BIN" --config "$WORK/n$i/config.json" >"$WORK/n$i.log" 2>&1 &
        echo $! > "$WORK/n$i.pid"
    done
    say "$NODES processes started: anchor n0 + $FOUNDERS founders (logs: $WORK/n*.log)"
}

stop() {
    for i in $(seq 0 $((NODES-1))); do
        [ -f "$WORK/n$i.pid" ] && kill "$(cat "$WORK/n$i.pid")" 2>/dev/null
    done
    wait 2>/dev/null
    say "stopped"
}

check() {
    FAILURES=0
    for i in $(seq 0 $((NODES-1))); do
        kill -0 "$(cat "$WORK/n$i.pid" 2>/dev/null)" 2>/dev/null || fail "node n$i is not running"
    done
    grep -q 'OPERATOR TRUST' "$WORK/n0.log" || fail "n0 did not announce operator trust (wrong binary or no operator_root_pubkey?)"
    grep -q 'phase Idle -> GenesisCollecting' "$WORK/n0.log" || fail "n0 never entered GenesisCollecting"
    grep -q 'genesis challenge ->' "$WORK/n0.log" || fail "n0 issued no genesis challenges"
    passed=$(grep -c 'genesis verdict for .*: PASSED' "$WORK/n0.log" || true)
    failed=$(grep -c 'genesis verdict for .*: failed' "$WORK/n0.log" || true)
    [ "$passed" -ge "$FOUNDERS" ] || fail "n0 recorded $passed PASSED genesis verdicts (need $FOUNDERS); $failed failed"
    grep -q 'genesis founding' "$WORK/n0.log" || fail "n0 never announced a founding"
    active=0
    for i in $(seq 1 $((NODES-1))); do
        if grep -qE 'phase .* -> Active' "$WORK/n$i.log"; then active=$((active+1)); fi
    done
    # The anchor (n0) collects and then idles; the founders go Active.
    [ "$active" -ge "$FOUNDERS" ] || fail "$active of $FOUNDERS founders went Active"
    grep -qE 'phase .* -> Active' "$WORK/n0.log" && fail "the genesis anchor n0 went Active (it must not found itself)"
    if [ "$FAILURES" -eq 0 ]; then
        say "PASS (operator trust): anchor + $FOUNDERS founders, $passed PASSED verdicts, founding announced, $active Active"
        return 0
    fi
    say "$FAILURES check(s) failed"
    return 1
}

case "$MODE" in
    start) provision; start ;;
    check) check ;;
    stop)  stop ;;
    run)
        provision
        start
        say "observing for ${WAIT}s..."
        sleep "$WAIT"
        check; rc=$?
        stop
        exit $rc
        ;;
    *) say "unknown mode '$MODE' (start|check|stop|run)"; exit 2 ;;
esac
