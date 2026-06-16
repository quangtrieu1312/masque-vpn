# masque-vpn

A **userspace VPN built on MASQUE** (IP-over-HTTP/3, [RFC 9484 CONNECT-IP](https://datatracker.ietf.org/doc/rfc9484/))
with a **kernel-bypass AF_XDP + eBPF datapath**. This is the **umbrella repo** that wires the
client and server together; the datapath internals live in
[**`tmasqued`**](https://github.com/quangtrieu1312/tmasqued), and the **head-to-head benchmarks vs
kernel WireGuard and a no-VPN baseline** (full matrix + caveats) live in
[**`tmasque-bench`**](https://github.com/quangtrieu1312/tmasque-bench).

- **[`client/`](https://github.com/quangtrieu1312/tmasque)** → `tmasque`: dials the server, manages
  the TUN + policy routing, pumps packets as QUIC datagrams.
- **[`server/`](https://github.com/quangtrieu1312/tmasqued)** → `tmasqued`: the AF_XDP datapath,
  in-kernel reverse NAT, control plane, and the performance work.

**The one file worth reading:**
[**`xdp.c`** — the eBPF XDP program that does reverse-NAT in-kernel on the return path](https://github.com/quangtrieu1312/tmasqued/blob/master/src/xdp/xdp.c).

---

## How the pieces fit together

```
┌─ tmasque (client) ─────────────────────────────────────┐
│ host applications send selected traffic through a      │
│ local TUN device (details in the tmasque repo)         │
└────────────────────────────────────────────────────────┘
             │  ▲
             ▼  │   QUIC / UDP :443 · HTTP/3 CONNECT-IP · mTLS
             │  │   inner IP carried in QUIC DATAGRAMs (tunnel CC off)
             │  │
┌─ tmasqued (server) ────────────────────────────────────┐
│ terminates the tunnel, then NATs and forwards          │
│ traffic both ways (internals in the tmasqued repo)     │
└────────────────────────────────────────────────────────┘
             │  ▲
             ▼  │   plain inner IP — ordinary kernel forwarding / NAT
             │  │
┌─ destination ──────────────────────────────────────────┐
│ a WAN host, a LAN host behind the server, or           │
│ another connected VPN client                           │
└────────────────────────────────────────────────────────┘
```

**What makes it interesting**
- **AF_XDP data plane** — packets move between the NIC and userspace without traversing the kernel
  network stack.
- **Return NAT in eBPF** — the DNAT return path runs entirely in the XDP program (`xdp.c`); no
  conntrack, no kernel-stack traversal.
- **No tunnel-level congestion control** — inner IP rides unreliable QUIC DATAGRAMs with the QUIC
  layer's CC disabled, so the inner TCP's own control loop governs the flow (no "TCP-over-TCP" collapse).

For how this performs against kernel WireGuard — full matrix, both directions, every NIC-steering
setting, with the honest caveats — see **[tmasque-bench](https://github.com/quangtrieu1312/tmasque-bench)**.
Both halves vendor forked **`quic-go`** and **`connect-ip-go`** for the CC-off datagram dataplane.

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

## Access control

Identity is the client's **mTLS cert CN**; the server maps **roles → resources (CIDR routes)**
and advertises only those — no resources, no routes. Manage by name with `tmasquectl` (see
Quick start) or the Unix-socket REST API; full model + endpoint reference live in
[**`tmasqued`**](https://github.com/quangtrieu1312/tmasqued#administration--tmasquectl).

---

## Repository layout

```
masque-vpn/
├── client/   → submodule: tmasque   (client)
├── server/   → submodule: tmasqued  (server + AF_XDP datapath + eBPF NAT)
└── README.md
```
