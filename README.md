# 0cdn

Small control plane, edge nodes, and a client. You run a server (API + optional DNS), one or more agents as exits, and a client that gets the exit list from the server and routes traffic through one of them. Auth is a token from the web dashboard.

Nodes use a 5-word ID (e.g. `apple:bridge:cloud:delta:echo`). You can dial a node by that ID: client asks the server for its address and connects. Client exposes SOCKS5; point your apps at it or use a TUN on Linux so all traffic goes through the overlay.

## What you run

- **Server** – API, SQLite, optional DNS for `.0cdn`. Auth, node list, lookup (node_id → address). `GET /health` and `GET /ready` for liveness/readiness.
- **Agent** – Runs on a box that acts as exit. Connects to server, listens for tunnels, can serve CDN and optionally TUN.
- **Client** – Fetches exits from server, picks one, runs local SOCKS5 (and optionally TUN). Your gateway.
- **Web UI** – Register, get a token, add nodes (5-word ID + address), manage `.0cdn` sites.

## Routing

`GET /api/routes` returns an ordered list of exits. If three or more nodes share the same location (country + city), server sorts by RTT (lowest first). Otherwise it uses availability (last_seen), geo, load. Client tries exits in order until one connects.

## 5-word IDs and lookup

Each agent (and P2P client if you use that) has a unique 5-word ID from a fixed list. Server stores that ID plus address, overlay_ip, and ICE candidates for P2P. When the client needs a node by ID it calls the lookup API (your nodes first, then P2P). If the server is blocked, client falls back to DHT: set `0CDN_DHT_BOOTSTRAP` (comma-separated addrs) or fetch from `GET /api/dht/bootstrap`. Agents and P2P nodes can announce to the DHT. Cache lookups with `0CDN_DHT_CACHE_TTL` (seconds).

In SOCKS5, to hit a service on a specific node (e.g. something on that node’s localhost), use the 5-word ID as host with dots instead of colons: `word.word.word.word.word`. P2P nodes behind NAT can register with `0CDN_P2P_ICE=1` (ICE via STUN); clients then use ICE to dial them.

## TUN overlay (Linux only)

Set `0CDN_TUN=1`: client (and optionally agent) creates a TUN and subnet 10.200.0.0/24. Each node gets an overlay_ip (10.200.0.x) from the server. Traffic into the TUN is encapsulated and sent to the exit; agents can forward overlay traffic to other 10.200.0.x via `GET /api/overlay/route`. You need CAP_NET_ADMIN or root. Set the exit with `0CDN_TUN_GW_ADDR` (direct addr) or `0CDN_EXIT_NODE_ID` (5-word ID; lookup then use that node as gateway). After the interface is up, set IP and routes with `ip addr` and `ip route`.

## Masking and transport

To make tunnel traffic look less like “0cdn protocol”:

- **QUIC** – `0CDN_USE_QUIC=1` uses QUIC on 443 (client tries QUIC first, then TCP). Agent listens QUIC on `0CDN_QUIC_ADDR` (default :443) and TCP on `0CDN_TCP_ADDR` (default :4433).
- **TLS** – `0CDN_MASK_TLS=1` wraps client–agent in TLS. Agent needs a cert (or generates self-signed; use `0CDN_TLS_CERT` and `0CDN_TLS_KEY` if you have your own).
- **Padding** – `0CDN_MASK_PADDING=1` adds random padding to data. Tune with `0CDN_MASK_PADDING_MAX` (default 64).
- **Morph** – `0CDN_MASK_MORPH=1` pads so frame sizes look more like HTTPS (256–1500 bytes) for DPI evasion.

## Quick start

Build:

```bash
make build
```

Or by hand: `go build -o server ./cmd/server` and same for agent, client.

Run the server (terminal 1):

```bash
0CDN_DB=./0cdn.db 0CDN_SERVER_ADDR=:8443 ./server
```

Run the web UI (terminal 2): `cd web && npm install && npm run dev`, then open http://localhost:3000. Register and copy your token. You’ll add your first node in the dashboard once the agent is running (agent prints its 5-word ID and address).

Run an agent (terminal 3):

```bash
0CDN_SERVER_URL=http://127.0.0.1:8443 0CDN_TOKEN=your_token ./agent
```

It prints node_id and listens on :4433. Add that node in the dashboard (address = IP:4433 or hostname:4433).

Run the client (terminal 4):

```bash
0CDN_SERVER_URL=http://127.0.0.1:8443 0CDN_TOKEN=your_token ./client
```

SOCKS5 is on 127.0.0.1:1080. Point your browser or app at that proxy.

Tests: `make test` or `go test ./internal/...`

Architecture and API map: [docs/SCHEME.md](docs/SCHEME.md).

Web UI: `cd web && npm install && npm run dev`, then http://localhost:3000. If the API is elsewhere set `NEXT_PUBLIC_API_URL`. Dashboard: regenerate token (old one stops working), nodes, sites. Settings: change password, Tor/I2P proxy.

## Config

See `configs/*.example.env` and the Config page in the web UI.

- **Server** – `0CDN_DB`, `0CDN_SERVER_ADDR`, `0CDN_DNS_ADDR` (optional, for .0cdn DNS). `0CDN_MAX_BODY_MB` (default 1, max 64). `GET /api/config` returns `stun_url`, `turn_url` from env.
- **Agent** – `0CDN_SERVER_URL`, `0CDN_TOKEN`, `0CDN_DATA`, `0CDN_TCP_ADDR`, `0CDN_QUIC_ADDR`, `0CDN_USE_QUIC`, `0CDN_HTTP_ADDR`. TUN: `0CDN_TUN=1`, overlay 10.200.0.0/24. DHT: `0CDN_DHT_LISTEN` for bootstrap. Masking: `0CDN_MASK_TLS`, `0CDN_MASK_PADDING`, `0CDN_MASK_MORPH`. PQ: `0CDN_PQ=1` (ML-KEM-768 + ChaCha20-Poly1305). Auth on wire: `0CDN_AGENT_AUTH=1`. Certs: `0CDN_TLS_CERT`, `0CDN_TLS_KEY`. Proxies: `0CDN_TOR_PROXY`, `0CDN_I2P_PROXY`.
- **Client** – Same server/token. `0CDN_SOCKS_ADDR` (default 127.0.0.1:1080). `0CDN_USE_QUIC` to prefer QUIC. TUN exit: `0CDN_EXIT_NODE_ID` (5-word) or `0CDN_TUN_GW_ADDR`. P2P: `0CDN_P2P_EXIT`, `0CDN_P2P_ICE`, `0CDN_P2P_ADDR`, `0CDN_P2P_LISTEN`, `0CDN_STUN_URL`. DHT: `0CDN_DHT_BOOTSTRAP`, `0CDN_DHT_CACHE_TTL`. PQ and Auth must match the agent. Lookup: `GET /api/nodes/lookup?node_id=...` returns addr, overlay_ip, ICE for P2P. `GET /api/config` for stun_url/turn_url.

## Security

Optional post-quantum (ML-KEM-768 + ChaCha20-Poly1305) on the tunnel layer.

## License

Apache 2.0. Author: parsend (c0redev).
