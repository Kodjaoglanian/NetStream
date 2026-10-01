# NexusMesh

A peer-to-peer mesh VPN for Linux: WireGuard-style cryptography, coordinated
NAT hole punching, a tiny centralized control plane, and full CLI/TUI
interfaces — all in Rust.

```
kernel ──▶ nexus0 (TUN) ──▶ nexus-agent ──▶ encrypted UDP ──▶ peer
                                      ▲
              nexus-server (control plane only: registry, IPAM,
              STUN rendezvous, WS signaling — payload stays opaque)
```

## Features

- **P2P data plane** — direct UDP transport between nodes; the server never
  sees traffic.
- **WireGuard crypto stack** — Noise_IKpsk2 handshake, X25519 + Ed25519,
  ChaCha20-Poly1305, TAI64N anti-replay, cookie DoS protection, 25 s
  keepalives, 2-minute rekey.
- **NAT traversal** — STUN + coordinated simultaneous punch bursts ordered
  by the control plane (`Punch` with `start_at_ms`).
- **Roaming** — the first authenticated packet from an address pins it as
  the peer's active endpoint.
- **Zero-infrastructure nodes** — `nexus up` auto-starts the daemon; keys
  and config persist in `/etc/nexus`.
- **CLI + TUI** — `nexus up/down/status/ping`, and a ratatui dashboard with
  live throughput charts and an event log (`nexus status --tui`).
- **systemd + installers** — one-liner deployment for server and agents.

## Quick start

```sh
# 1. On a public VPS:
curl -fsSL https://raw.githubusercontent.com/Kodjaoglanian/NetStream/main/scripts/install-server.sh | sudo sh
#    → prints a bootstrap key: nexus_sec_...

# 2. On each node:
curl -fsSL https://raw.githubusercontent.com/Kodjaoglanian/NetStream/main/scripts/install-agent.sh | \
    sudo sh -s -- --server http://<SERVER>:8080 --authkey nexus_sec_...

# 3. Verify:
nexus status
nexus ping 100.64.0.2
nexus status --tui
```

Every node gets a `/16` virtual IP in `100.64.0.0/16` reachable from every
other node, end-to-end encrypted.

## CLI

```
nexus up --server <URL> --authkey <KEY>   join the mesh
nexus down                              disconnect (daemon keeps running)
nexus status                            peers table: vip, mode, endpoint, rtt, rx/tx
nexus status --tui                      interactive dashboard
nexus ping <VIP>                        encrypted ICMP echo + RTT
nexus daemon stop                       stop the agent
```

## Server admin

```
nexus-server serve                      run control plane
nexus-server issue-key --label x [--reusable]
nexus-server list-keys | list-nodes
nexus-server revoke-node <id>           frees the VIP
nexus-server rotate-token <id>          force credential rotation
```

## Building

```sh
cargo build --release          # whole workspace
cargo test --workspace         # unit + integration tests
cargo clippy --all-targets --all-features -- -D warnings
```

Releases: push a tag `v*.*.*` → CI builds `x86_64`/`aarch64` ×
`gnu`/`musl` tarballs + SHA256s and publishes a GitHub release.

## Docs

- `docs/architecture.md` — components, data flow, failure handling
- `docs/protocol.md` — wire format, handshake, STUN, IPC
- `docs/api.md` — REST + WebSocket control-plane reference
- `docs/manual.md` — install, ops, firewalling, troubleshooting
