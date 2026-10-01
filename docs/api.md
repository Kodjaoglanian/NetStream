# NexusMesh Control-Plane API

Base URL: `http(s)://<server>:8080` (default listen `0.0.0.0:8080`).
Auth: `Authorization: Bearer <session-token>` on all `/v1/*` routes except
`/v1/register` (which authenticates via the `nexus_sec_` auth key) and the
health endpoints.

## REST

| Method | Path              | Auth    | Purpose |
|--------|-------------------|---------|---------|
| GET    | `/healthz`        | none    | liveness probe — `200 ok` |
| GET    | `/metrics`        | none    | Prometheus-ish text counters |
| POST   | `/v1/register`    | authkey | register a node, returns VIP + token |
| GET    | `/v1/nodes`       | bearer  | list every registered node |
| GET    | `/v1/nodes/self`  | bearer  | the caller's own record |
| POST   | `/v1/endpoints`   | bearer  | replace reported endpoint list |
| GET    | `/v1/signal`      | bearer  | WebSocket signaling channel |

### `POST /v1/register`

```json
{
  "authkey": "nexus_sec_xxxxxxxx",
  "node_name": "laptop-alice",
  "identity_pubkey": "<64 hex ed25519>",
  "wg_pubkey": "<64 hex x25519>",
  "signature": "<128 hex ed25519 sig over wg_pubkey bytes>",
  "endpoints": ["192.168.1.20:51820"]
}
```

`200 OK`:

```json
{
  "node_id": 7,
  "vip": "100.64.0.7",
  "token": "nx_tok_…",
  "stun_port": 3478,
  "peers": [ { "node_id": 3, "name": "gw", "vip": "100.64.0.3",
               "identity_pubkey": "…", "wg_pubkey": "…",
               "endpoints": ["203.0.113.9:51820"], "online": true } ]
}
```

Errors: `400` malformed body, `401` bad/consumed authkey or bad signature,
`409` key already registered, `503` IPAM exhausted.

### `GET /v1/nodes` / `GET /v1/nodes/self`

`200 OK` → `{ "nodes": [PeerInfo…] }` or one `PeerInfo`.

### `POST /v1/endpoints`

```json
{ "endpoints": ["198.51.100.4:51820", "192.168.1.20:51820"] }
```

Replaces the node's reported endpoint list; the server pushes a
`PeerUpdated` to every connected peer.

## WebSocket `/v1/signal?token=…`

JSON frames (`SignalMessage`), snake_case `type` tag.

Server → node:

```json
{"type":"welcome","peers":[PeerInfo…],"stun_port":3478}
{"type":"peer_joined","peer":{…}}
{"type":"peer_left","node_id":7}
{"type":"peer_updated","peer":{…}}
{"type":"punch","peer_node_id":3,"peer_vip":"100.64.0.3",
 "peer_wg_pubkey":"…","endpoints":["…"],"start_at_ms":1730000000123}
```

Node → server:

```json
{"type":"report_endpoints","endpoints":["…"]}
{"type":"punch_request","target_node_id":3}
{"type":"heartbeat"}
```

`401` on upgrade = token rejected → agent re-registers automatically.

## CLI admin surface (`nexus-server`)

```
nexus-server serve   --listen 0.0.0.0:8080 --stun-listen 0.0.0.0:3478 \
                     --db /var/lib/nexus/nexus.db
nexus-server issue-key   --db <db> --label <label> [--reusable]
nexus-server list-keys   --db <db>
nexus-server list-nodes  --db <db>
nexus-server revoke-node --db <db> <node_id>
nexus-server rotate-token --db <db> <node_id>
```

Env vars: `NEXUS_LISTEN`, `NEXUS_STUN_LISTEN`, `NEXUS_DB`.
