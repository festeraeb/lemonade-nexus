---
layout: default
title: Operator Trust Bootstrap
---

# Bootstrapping an operator-trust network (fork only)

This is how we brought up a self-hosted Nexus network on ordinary Intel servers, put Lemonade on it as a
Tier 3 inference node, and reached it from a laptop-style client. Every step below was run on
2026-10-30/31 on four machines (t440, c4, c2, c3). Read [Operator-Trust.md](Operator-Trust.md) first:
**this is operator trust, not hardware trust.** It does not replace SEV-SNP.

Names in angle brackets are yours to fill in. Never paste a link token, the operator root key file, or a
control token into a log, a ticket or a chat.

## 0. What you need

- Five servers that can reach each other over UDP and TCP, plus one more process to act as the genesis
  anchor. The anchor admits peers and never founds itself, so "5 founders" is **6 processes**. Two
  processes may share a host, but then losing that host loses two founders.
- Genesis needs exactly 5 founders (`kBootstrapThreshold = 5`). With 6 to 9 servers you still get a
  5-member Tier 1; the rest wait as Tier 2 reserves. A 7-member Tier 1 needs 10 admitted servers.
- The fork built with the option on:

  ```
  cmake -S . -B build-operator -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_TESTING=ON -DLEMONADE_NEXUS_OPERATOR_TRUST=ON
  cmake --build build-operator --target lemonade-nexus LemonadeNexusSidecar
  ./build-operator/tests/test_security_attestation --gtest_filter='OperatorEnrolled*'   # expect 20 passed
  ```

  We built once on the host with the oldest glibc and copied the binary to the others.

## 1. Try it on one machine first

```
FOUNDERS=5 WAIT=120 BIN=build-operator/projects/LemonadeNexus/lemonade-nexus scripts/operator-mesh.sh run
```

PASS means: 5 PASSED genesis verdicts, `genesis founding: 5 attested founders`, and every founder logs
`phase AwaitingBootstrap -> Active: epoch 1 adopted and active`. The script shows every command the
multi-host setup needs.

## 2. Make identities and the operator root key

On each server, for each process:

```
lemonade-nexus --first-run --data-root <data_root>
# prints "Identity pubkey: ..." and "Gossip pubkey: ..."
```

On the anchor host only (keep this file off the other servers; it is the whole trust model):

```
lemonade-nexus --operator-keygen <operator-root.json>      # 0600; prints only the public key
```

## 3. Enroll each server twice: as a member, and by the operator

For every process, using the anchor's data root and the anchor's gossip key as the genesis key:

```
lemonade-nexus --enroll-server <gossip_b64> <name> --data-root <anchor data_root> \
               --root-pubkey <anchor identity hex> --genesis-pubkey <anchor gossip_b64>
# copy <anchor data_root>/identity/server_cert_<name>.json to <data_root>/identity/server_cert.json on that server

lemonade-nexus --operator-enroll <gossip_b64> --operator-keyfile <operator-root.json> \
               --genesis-pubkey <anchor gossip_b64> --data-root <anchor data_root> \
               --operator-enroll-out <name>.enrollment.json
# copy to <data_root>/security/attestation-cache/operator-enrollment.json on that server
```

Optional: `--operator-binary-sha256 <hex>` pins the server binary. The pin is a self-report the server
compares with your pin; it is not a measurement.

## 4. Configure, give each server a certificate, start

Every server's config needs `operator_root_pubkey` (the public key from step 2), its seeds and ports,
and these three so the names are yours: `dns_base_domain` (we used `nexus.cesarops.lan`), `region`
(`lan`), `server_hostname` (the process name).

**TLS is not optional.** Both API listeners stay closed until a certificate exists; there is no plaintext
fallback. Without public DNS and ACME, make a small LAN test CA and issue, for each server,
`<id>.<region>.seip.<dns_base_domain>` and `private.<id>.<region>.seip.<dns_base_domain>` into
`<data_root>/certs/<fqdn>/{fullchain.pem,privkey.pem}`. The server logs
`[AcmeService] found valid certificate for ...` and then `All services started. HTTPS:<port>`.
Make those names resolve on every client host (we used `/etc/hosts`).

Run each process as a long-lived service. Start the anchor first, then the founders. Expect, on the anchor:

```
[warning] OPERATOR TRUST: Tier 1 under operator enrollment (root ...), not hardware attestation
[info] [security] genesis verdict for <node>: PASSED (failure=0)        x5
[info] [security] genesis founding: 5 attested founders
```

and on every founder `phase AwaitingBootstrap -> Active: epoch 1 adopted and active`. On our four hosts,
activation came 78 s after the last verdict.

## 5. The first client device

Clients trust the test CA **per process**, not system-wide: set `SSL_CERT_FILE=<ca.crt>` in that
service's environment only. Every client must pin the genesis key before any tree call.

Sidecar config for the first device (it joins with no invite and gets a group of its own):

```json
{
  "server": "<founder fqdn>:<https port>",
  "tls": true,
  "data_root": "<client data dir>",
  "genesis_key": "<anchor gossip_b64>",
  "mesh_port": 13306,
  "link_token_out": "<client data dir>/invite.json",
  "link_token_perms": ["read", "connect_private", "svc:inference"]
}
```

```
lemonade-nexus-sidecar --config client.json
# joined network: node_id=..., tunnel_ip=10.x.x.x/32
# Invite for this group written to invite.json        (0600)
# Mesh port on 127.0.0.1:13306
```

The SDK logs `verified Tier 1 epoch 1: 5 member(s)` once it has walked the authority chain.

Invites are single-use, and each sidecar start writes a new `invite.json`. Hand an invite to exactly one
device, then delete it from wherever you put it.

## 6. Put Lemonade on the mesh as Tier 3

Two ways. Both expose the Lemonade server at mesh vport 13305 with a service catalog, so `svc:inference`
gates it.

**a) Stock Lemonade, unchanged, behind the sidecar:**

```json
{
  "server": "<founder fqdn>:<https port>", "tls": true, "data_root": "<dir>",
  "genesis_key": "<anchor gossip_b64>",
  "inference": true,
  "catalog": "<dir>/catalog.json",
  "expose": ["13305:<lemonade port>"]
}
```

with the invite in the environment (`LN_SIDECAR_LINK_TOKEN`, from a 0600 EnvironmentFile). The catalog
we used has a family `inference` (GET `/api/v1/models`, `/api/v1/health`, `/v1/models`; POST
`/api/v1/chat/completions`, `/api/v1/completions`, `/v1/chat/completions`) and a family `management`
(prefix `/api/v1/`). Logs: `Joining as a Tier 3 inference node`, `Exposed 127.0.0.1:<port> at mesh :13305`,
`Registered service catalog on mesh :13305`.

**b) Our Lemonade fork, which joins by itself** (`festeraeb/lemonade-iced-lemcake`, branch
`iced-lemcake/nexus-tier3-2026-10-30`; lemond loads `liblemonade_nexus_sdk.so` at run time and is unchanged
without the block):

```json
"nexus": {
  "enabled": true,
  "server": "<founder fqdn>:<https port>", "tls": true,
  "sdk_library": "<path>/liblemonade_nexus_sdk.so",
  "data_root": "<dir>",
  "genesis_key": "<anchor gossip_b64>",
  "device_name": "<name shown to clients>",
  "vport": 13305
}
```

plus `LEMONADE_NEXUS_LINK_TOKEN` in the environment for the first join only. Logs:
`Nexus: joined as a Tier 3 inference node`, `Nexus: exposing tcp:127.0.0.1:<port> at mesh :13305`.
After the first join the identity is enrolled; remove the token.

Check from the client:

```
curl -s 127.0.0.1:13306/api/v1/models | jq -r '.data[].id' | cut -d/ -f1 | sort -u
curl -s -X POST 127.0.0.1:13306/api/v1/chat/completions \
  -d '{"model":"<device>/<model>","messages":[{"role":"user","content":"Say ok."}],"max_tokens":8}'
```

Name the model **without** a device prefix to let the mesh port choose; with this fork it re-sends once
to the next device if the chosen one gives no answer.

Two Lemonade notes from our runs: set `llamacpp.cuda_bin` to the llama-server **file**, not its folder;
and load the model once with `--save-options` (e.g. `--llamacpp cuda`), or after a restart Lemonade may
auto-load it on its default backend (for us, CPU at a sixth of the speed).

## 7. A service that trusts the mesh identity (example: nauti-nodes)

Expose the service from a device (`"expose": ["<vport>:<port>"]`) with a catalog family for it. The
ingress strips any `X-Nexus-*` headers the caller sent and sets the real peer attribution. So:

- **Bind the service to loopback.** Otherwise anyone on the LAN can send the headers themselves.
- Trust the headers, never a body field. In our test a body `node_id` that disagreed with the
  attributed peer got 403, and a request with no attribution got 403.
- `svc:` permissions named in an invite were **not** granted to the joining device. The group owner had to
  assign them: `POST /api/tree/node/assignments/<group>` with
  `{"pubkey": "<peer mgmt key>", "permissions": [..., "svc:<family>"]}` (sidecar control route `/assign`),
  then refresh the peer list.

## 8. Known gaps

- An invite minted through one Tier 1 server was refused by another for at least 8 minutes; join through
  the server that issued it.
- The client's peer list (`is_online`) lags by tens of seconds after a device stops or comes back.
  Routing does not wait for it.
- Everything above is a test network. We have not run it across the internet, behind NAT on both ends, or
  for longer than a day.

## 9. Taking it down

Stop and remove the services, delete the data roots, and remove the `/etc/hosts` lines and any firewall
openings you added. The operator root key file is the one thing to destroy on purpose.
