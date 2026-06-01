# masque-vpn

A **userspace VPN built on MASQUE** (IP-over-HTTP/3, [RFC 9484 CONNECT-IP](https://datatracker.ietf.org/doc/rfc9484/))
with a **kernel-bypass AF_XDP + eBPF datapath**. This is the **umbrella repo** that wires the
client and server together; the datapath internals and the **head-to-head benchmarks against
kernel WireGuard and a no-VPN direct baseline** live in
[**`tmasqued`**](https://github.com/quangtrieu1312/tmasqued).

- **[`client/`](https://github.com/quangtrieu1312/tmasque)** → `tmasque`: dials the server, manages
  the TUN + policy routing, pumps packets as QUIC datagrams.
- **[`server/`](https://github.com/quangtrieu1312/tmasqued)** → `tmasqued`: the AF_XDP datapath,
  in-kernel reverse NAT, control plane, and the performance work.

**The interesting code:** &nbsp;
[**`xdp.c`** — the eBPF XDP/NAT program](https://github.com/quangtrieu1312/tmasqued/blob/master/src/xdp/xdp.c) ·
[**`tmasqued`** — server + AF_XDP datapath](https://github.com/quangtrieu1312/tmasqued) ·
[**`tmasque`** — client](https://github.com/quangtrieu1312/tmasque)

---

## How the pieces fit together

```
  ┌──────────────────┐               ┌────────────────────────────────────────┐
  │ tmasque (client) │               │ tmasqued (server)                      │
  │                  │               │                                        │
  │ app → TUN        │ ─── QUIC ───→ │ :443 → decap → SNAT → forward TX       │  ──→ WAN
  │                  │               │                                        │
  │ app ← TUN        │ ←─── QUIC ─── │ QUIC datagram ← in-kernel DNAT (xdp.c) │  ←── WAN
  │                  │               │                                        │
  │ inner TCP → BBR  │               │ control plane: SQLite +                │
  └──────────────────┘               │ Unix-socket REST API                   │
                                     └────────────────────────────────────────┘

  link:  QUIC / UDP :443 · HTTP/3 CONNECT-IP · mTLS (Ed25519)
         inner IP in QUIC DATAGRAMs (unreliable; tunnel CC off)
```

**What makes it interesting**
- **AF_XDP data plane** — packets move between the NIC and userspace without traversing the kernel
  network stack.
- **Return NAT in eBPF** — the DNAT return path runs entirely in the XDP program (`xdp.c`); no
  conntrack, no kernel-stack traversal.
- **No tunnel-level congestion control** — inner IP rides unreliable QUIC DATAGRAMs with the QUIC
  layer's CC disabled, so the inner TCP's own control loop governs the flow (no "TCP-over-TCP" collapse).

For how this performs against kernel WireGuard, with the full matrix and the honest caveats, see
**[tmasqued › Performance](https://github.com/quangtrieu1312/tmasqued#performance)**. Both halves
vendor forked **`quic-go`** and **`connect-ip-go`** for the CC-off datagram dataplane; details there.

Each submodule's README has the component-level detail.

---

## Quick start

```sh
# Server
cd server
cp tmasqued.conf.template tmasqued.conf      # WAN_INTERFACE, TUNNEL_IP, CLIENT_CIDR, SANs…
sudo docker compose up --build -d            # builds binary + eBPF, bootstraps CAs, starts
# manage by name via tmasquectl (runs inside the container):
ctl() { sudo docker compose exec tmasqued tmasquectl "$@"; }
ctl client create alice               # client + default role "alice" + cert bundle
ctl resource create internet 0.0.0.0/0   # full tunnel — route all traffic through the VPN
ctl role assign alice internet           # link it to alice's role — WITHOUT this she gets no routes
#   → bundle at server/certs/client/alice/bundle.zip

# Client (on the client machine)
mkdir -p /etc/tmasque/certs && unzip ~/bundle.zip -d /etc/tmasque/certs
cd client
cp tmasque.conf.template /etc/tmasque/tmasque.conf   # set SERVER=host:443
./build.sh && sudo ./build/tmasque
```

Requirements: Linux, Docker, `/dev/net/tun`, `NET_ADMIN` (plus `NET_RAW` on the server); an
XDP-capable NIC/driver on the server. First boot generates the server + client CAs (Ed25519) and
runs DB migrations.

---

## Access control & management

Identity is the **mTLS certificate CN** (= client DB id). On connect the server
resolves the client's **roles → resources (CIDR prefixes)** and advertises those as
routes — a client with no resources gets no routes. Clients, roles, resources, and the
DHCP pool are administered through a small **REST API over a Unix socket**
(`/var/run/tmasqued.sock`); all keys are Ed25519 and the server requires + verifies
client certs.

Full endpoint reference (payloads, by-name variants, DHCP):
[**`tmasqued/src/README.md`**](https://github.com/quangtrieu1312/tmasqued/blob/master/src/README.md).

---

## Repository layout

```
masque-vpn/
├── client/   → submodule: tmasque   (client)
├── server/   → submodule: tmasqued  (server + AF_XDP datapath + eBPF NAT)
└── README.md
```
