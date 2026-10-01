# NexusMesh Operations Manual

## Requirements

- Linux kernel ≥ 5.4 (TUN driver — `/dev/net/tun`).
- Root (or `CAP_NET_ADMIN`) for `nexus-agent`.
- `ip` tool (`iproute2`) for interface configuration.
- A public VPS for `nexus-server` with TCP/8080 + UDP/3478 open
  (both configurable).

## Install

### Control plane (VPS)

```sh
curl -fsSL https://raw.githubusercontent.com/Kodjaoglanian/NetStream/main/scripts/install-server.sh | sudo sh
```

This detects the arch, verifies the release's SHA256, installs
`nexus-server` to `/usr/local/bin`, creates the `nexus` system user and
`/var/lib/nexus`, installs/enables `nexus-server.service`, and prints a
bootstrap `nexus_sec_…` key + the agent join command.

### Nodes

```sh
curl -fsSL https://raw.githubusercontent.com/Kodjaoglanian/NetStream/main/scripts/install-agent.sh | \
    sudo sh -s -- --server http://VPN_IP:8080 --authkey nexus_sec_...
```

Installs `nexus-agent`, `nexus`, `nexus-tui`, writes
`/etc/nexus/config.json`, enables `nexus-agent.service`, and joins the mesh
immediately.

## Day-2 operations

### Issue / manage keys

```sh
nexus-server issue-key --label alice --reusable     # multi-use key
nexus-server issue-key --label bob                  # one-shot
nexus-server list-keys
nexus-server list-nodes
nexus-server revoke-node 7                          # frees VIP
nexus-server rotate-token 7                         # forces re-auth
```

### Node side

```sh
nexus up --server http://vpn:8080 --authkey nexus_sec_...
nexus status                  # table: vip, endpoint, rtt, rx/tx
nexus status --tui            # interactive dashboard
nexus ping 100.64.0.3         # encrypted ICMP echo + RTT
nexus down                    # tear down tunnel (daemon keeps running)
nexus daemon stop             # stop the agent entirely
```

Config lives in `/etc/nexus/`:

| file           | contents |
|----------------|----------|
| `config.json`  | server URL, token, node id, VIP, port, name (0600) |
| `identity.key` | Ed25519 identity (0600, generated once) |
| `wg.key`       | X25519 static key (0600, generated once) |

Optional `/etc/nexus/agent.env` (systemd `EnvironmentFile`):

```sh
NEXUS_LISTEN_PORT=51820
NEXUS_CONFIG=/etc/nexus/config.json
NEXUS_SOCK=/var/run/nexus.sock
RUST_LOG=info
```

### Server side

`/etc/nexus/server.env`:

```sh
NEXUS_LISTEN=0.0.0.0:8080
NEXUS_STUN_LISTEN=0.0.0.0:3478
NEXUS_DB=/var/lib/nexus/nexus.db
RUST_LOG=info
```

## Firewall rules (server)

```sh
ufw allow 8080/tcp   # HTTP + WS
ufw allow 3478/udp   # STUN
```

Agents only need outbound UDP (any port) plus the UDP listen port if you
want inbound-initiated connectivity — hole punching works without it.

## Troubleshooting

| Symptom | Check |
|---------|-------|
| `nexus status` → "connect … nexus.sock: No such file" | agent not running: `systemctl start nexus-agent` or any `nexus up` will spawn it |
| `connect failed: registration failed: 401` | authkey wrong/consumed; issue a new one (`list-keys` shows usage) |
| peers listed but `mode: pending` | NAT punch in progress or blocked UDP; check `journalctl -u nexus-agent` and that UDP/51820 isn't filtered |
| `ping` times out | verify both agents show `mode: direct`; `nexus status` RTT column stays `—` until a pong returns |
| TUN errors at start | `/dev/net/tun` missing → `modprobe tun` |
| STUN endpoint `—` | UDP/3478 unreachable on the server |

## Security notes

- Payload traffic is E2E encrypted; the server never sees plaintext.
- Auth keys are stored as hashes; session tokens rotate on `rotate-token`.
- `mac1` covers every handshake datagram; a cookie challenge gates
  handshake CPU under flood (>12 init/s per source window).
- Every transport packet's inner source IP is bound to the sender's
  assigned VIP — VIP spoofing inside the mesh is dropped.
