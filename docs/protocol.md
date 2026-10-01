# NexusMesh Wire Protocol

All multi-byte integers are **little-endian** unless noted. All crypto is
BLAKE2s / ChaCha20-Poly1305 / X25519 / Ed25519.

## 1. UDP datagram types

Every NexusMesh datagram begins with a 4-byte header:

```
+-----------+------------------------------+
| type u8   | reserved0[3] = 0             |
+-----------+------------------------------+
```

| type | message          | length      |
|------|------------------|-------------|
| 1    | initiation       | 148 B       |
| 2    | response         | 92 B        |
| 3    | cookie reply     | 64 B        |
| 4    | transport        | 32 + n      |
| 5    | NAT punch        | 56 B        |

STUN (RFC 5389) datagrams are recognized by the `0x2112A442` magic cookie
and are handled *before* the type dispatch.

### 1.1 Handshake initiation (type 1, 148 B)

```
type(u8)=1 reserved[3] sender_index u32
unencrypted_ephemeral[32] encrypted_static[48] encrypted_timestamp[28]
mac1[16] mac2[16]
```

- `sender_index` — initiator's random session index.
- `unencrypted_ephemeral` — initiator X25519 ephemeral public key.
- `encrypted_static` — AEAD(chaining_key) of initiator static pubkey.
- `encrypted_timestamp` — AEAD of TAI64N(12 B).
- `mac1` — BLAKE2s-128 keyed MAC over bytes 0..116 with
  `key = BLAKE2s(b"mac1----" || responder_static_pubkey)`.
- `mac2` — `0` normally; or BLAKE2s-128 keyed by the responder's cookie
  when replying to a cookie challenge.

### 1.2 Handshake response (type 2, 92 B)

```
type(u8)=2 reserved[3] sender_index u32 receiver_index u32
unencrypted_ephemeral[32] encrypted_nothing[16] mac1[16] mac2[16]
```

### 1.3 Cookie reply (type 3, 64 B)

```
type(u8)=3 reserved[3] receiver_index u32 nonce[24] encrypted_cookie[32]
```

Sent under load; the cookie binds the initiator's IP:port (secret =
responder static key, AEAD-sealed, keyed MAC1 as AAD). The initiator then
recomputes `mac2 = MAC(cookie, initiation[0..132])` and retransmits.

### 1.4 Transport (type 4)

```
type(u8)=4 reserved[3] receiver_index u32 counter u64 encrypted_packet[n+16]
```

`encrypted_packet` = ChaCha20-Poly1305(send_key, counter) of the raw IP
packet. Empty plaintext = keepalive. `receiver_index` selects the session;
`counter` feeds the 2048-packet replay window.

### 1.5 NAT punch (type 5, 56 B)

```
type(u8)=5 reserved[3] static_pubkey[32] nonce u64 padding[12]
```

Unauthenticated by design (it precedes the session). Peers ignore punches
from unknown public keys; a valid punch marks the source address as an
active endpoint candidate and triggers a symmetric reply.

## 2. Handshake (Noise_IKpsk2)

Identical construction to WireGuard:

- `ck = BLAKE2s(b"Noise_IKpsk2_0 ^ 0" || LABEL)` construction hash chain.
- DH triplets: DH(static_i, static_r), DH(eph_i, static_r), DH(eph_i, eph_r)
  folded into `ck` via HKDF-BLAKE2s(ck, dh_out).
- TAI64N timestamp is AEAD-sealed into the initiation; responders enforce
  monotonicity to kill replays.
- `SessionKeys { send_key, recv_key, their_index, our_index }` via
  `HKDF(ck, ε, 2)`: initiator uses (k1 send, k2 recv), responder reversed.

## 3. STUN (RFC 5389 subset)

`BINDING REQUEST` → `BINDING RESPONSE` with `XOR-MAPPED-ADDRESS`. Used by
agents against the server's UDP/3478 responder every 30 s while connected
to refresh the observed public endpoint (port-sensitive NATs need this).

## 4. Control-plane HTTP/WS API

See `docs/api.md` for the REST surface. The WS protocol (`/v1/signal`)
exchanges JSON `SignalMessage` frames:

- server→node: `Welcome { peers }`, `PeerJoined`, `PeerLeft`,
  `PeerUpdated`, `Punch { endpoints, start_at_ms }`
- node→server: `ReportEndpoints { endpoints }`, `PunchRequest
  { target_node_id }`, `Heartbeat`

`Punch.start_at_ms` is a UNIX-ms timestamp both sides wait for before
spraying punch datagrams — synchronized bursts keep symmetric NAT mappings
guessing-friendly.

## 5. Local IPC

Unix socket `/var/run/nexus.sock`, NDJSON:

```json
{"cmd":"connect","server_url":"...","authkey":"..."}
{"cmd":"disconnect"}  {"cmd":"shutdown"}  {"cmd":"status"}
{"cmd":"ping","vip":"100.64.0.2"}
```

Responses: `{"kind":"ok","message":"…"}`, `{"kind":"error","message":"…"}`,
`{"kind":"status","report":{…}}`, `{"kind":"pong","vip":"…","rtt_ms":12.4}`.
