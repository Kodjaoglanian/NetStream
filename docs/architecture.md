# NexusMesh Architecture

NexusMesh is a peer-to-peer mesh VPN: a small centralized **control plane**
(`nexus-server`) plus a **node agent** (`nexus-agent`) on every machine. The
control plane only brokers identity, IP addresses, and rendezvous signals —
all payload traffic is end-to-end encrypted between agents and is *opaque* to
the server.

```
                    ┌───────────────────────────┐
                    │        nexus-server        │
                    │  axum HTTP + WS (signal)   │
                    │  SQLite: nodes/keys/IPAM   │
                    │  UDP 3478: STUN responder  │
                    └─────────────┬─────────────┘
                 register /v1/register      /v1/signal?token=…
              ┌──────────────────┼──────────────────┐
              │ WS               │ WS               │
     ┌────────▼───────┐  ┌───────▼────────┐  ┌──────▼─────────┐
     │  nexus-agent A │  │ nexus-agent B  │  │  nexus-agent C │
     │  ┌──────────┐  │  │  ┌──────────┐  │  │  ┌──────────┐  │
     │  │ tun nexus0│  │  │  │ tun nexus0│  │  │  │ tun nexus0│ │
     │  └────┬─────┘  │  │  └────┬─────┘  │  │  └────┬─────┘  │
     │  engine: UDP   │  │  engine: UDP   │  │  engine: UDP   │
     │  noise + punch │  │  noise + punch │  │  noise + punch │
     │  IPC unix sock │  │  IPC unix sock │  │  IPC unix sock │
     └───────┬────────┘  └───────┬────────┘  └───────┬────────┘
             │                   │                   │
             │  encrypted UDP transport (data plane) │
             └───────── direct P2P mesh ─────────────┘

   nexus / nexus-tui ── unix socket ──▶ nexus-agent (local control)
```

## Crates

| Crate          | Role                                                        |
|----------------|-------------------------------------------------------------|
| `nexus-core`   | Shared models, wire protocol, Noise handshake, AEAD, STUN, IPC |
| `nexus-server` | Control plane: REST API, WS signaling, SQLite IPAM, STUN    |
| `nexus-agent`  | Node daemon: TUN device, UDP datapath, hole punching, IPC   |
| `nexus-cli`    | `nexus` binary — up/down/status/ping, daemon management     |
| `nexus-tui`    | `nexus-tui` — ratatui dashboard (peers, throughput, events) |

## Control plane

- **Registration** — `POST /v1/register` with a `nexus_sec_…` auth key
  (issued by `nexus-server issue-key`), the node's Ed25519 identity pubkey,
  its X25519 static pubkey, and a signature proving key ownership. The server
  allocates a virtual IP from `100.64.0.0/16` and returns a session token.
- **Signaling** — `GET /v1/signal?token=…` upgrades to a WebSocket. The server
  pushes `Welcome { peers }`, `PeerJoined/Left/Updated`, and relays
  `Punch` coordination between nodes that want to connect.
- **STUN** — UDP 3478 RFC 5389 binding responder so each node learns its
  public `ip:port` as seen from the internet.
- **State** — embedded SQLite (`rusqlite`) holds auth key hashes (plaintext
  keys are never stored), nodes, VIPs, endpoints, and session tokens.

## Data plane

- **TUN** — `nexus0` (`/dev/net/tun`, IFF_TUN|IFF_NO_PI), assigned
  `VIP/16` with MTU 1400. Every packet read from TUN is routed by
  destination IP → peer lookup → encrypted UDP datagram.
- **Handshake** — WireGuard's `Noise_IKpsk2` pattern with BLAKE2s chaining
  key and TAI64N timestamps for responder replay protection. One ephemeral
  X25519 per handshake, sessions keyed with HKDF-BLAKE2s.
- **Transport** — ChaCha20-Poly1305, u64 send counters, receiver indices for
  peer/session lookup, sliding replay window (2048 packets).
- **Cookie DoS** — under load (>12 initiations/s) responders answer with a
  stateless MAC'd cookie reply instead of doing expensive crypto.
- **NAT traversal** — agents report LAN + STUN-observed endpoints to the
  server; when two peers want a path the server orders a *simultaneous punch
  burst* (`Punch` message with a `start_at` timestamp), both sides spray
  40 punch datagrams @20 ms at every candidate endpoint, opening cone and
  symmetric NAT bindings. First authenticated transport packet pins the
  active endpoint (WireGuard-style roaming).
- **Keepalive/rekey** — 25 s empty-keepalive for idle sessions, rekey at
  110 s or 2^60 messages, hard reject at 180 s.

## IPC

`/var/run/nexus.sock`, newline-delimited JSON (`IpcRequest`/`IpcResponse`).
`nexus` and `nexus-tui` are dumb clients — all state lives in the engine.

## Failure handling

- WS signaling supervisor: exponential backoff (1 s → 30 s), heartbeats.
- 401 from signaling → agent wipes the token and re-registers with its
  saved auth key automatically.
- `nexus up` waits for the mesh join (20 s timeout) and reports failure
  instead of exiting silently.
