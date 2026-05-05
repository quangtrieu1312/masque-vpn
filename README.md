# masque-vpn

A VPN implementation built on top of the [MASQUE](https://ietf-wg-masque.github.io/) protocol — IP tunneling over HTTP/3 and QUIC. The server supports multiple simultaneous clients with per-client IP assignment, role-based access control, and a Unix socket management API.

---

## How it works

```
Client (masque)                Server (masqued)
  │                              │
  │── QUIC (UDP/443) ──────────► │
  │   HTTP/3 CONNECT-IP          │
  │   mTLS (Ed25519)             │
  │◄─ IP prefix assigned ────── │
  │◄─ routes advertised ─────── │
  │                           TUN device
  │                           raw socket → WAN
```

The client (`masque`) establishes a QUIC connection to the server (`masqued`), upgrades it to an HTTP/3 `CONNECT-IP` session, and receives a `/32` IP address and a set of routes from the server. The server creates a TUN device and multiplexes packets from all connected clients using a per-client channel map keyed by assigned IP.

Client identity is derived from the **Common Name** of the client's mTLS certificate, which is set to the client's database ID at cert generation time. This is how the server looks up per-client routes at connection time.

---

## Repository layout

```
masque-vpn/
├── client/
│   ├── src/                    # Go source (main.go, logger.go, ip.go, rand.go)
│   ├── masque.conf.template    # Client config template
│   ├── Dockerfile              # Runtime image
│   ├── Dockerfile.build        # Build-only image (golang:tip-alpine3.22)
│   ├── docker-compose.yml      # Example multi-client compose file
│   └── build.sh                # Local Docker-based build script
│
└── server/
    ├── src/                    # Go source
    │   ├── main.go             # Server entrypoint, QUIC listener, TUN device
    │   ├── management.go       # Unix socket HTTP management API
    │   ├── config/             # Config file loader
    │   ├── constants/          # Compile-time path constants
    │   ├── db/                 # SQLite connection
    │   ├── domain/             # Data models (Client, Role, Resource, DHCP)
    │   ├── migration/          # Schema migrations
    │   ├── repository/         # SQL queries
    │   ├── request/            # API request types
    │   ├── service/            # Business logic
    │   └── utility/            # IP math, raw socket helpers
    ├── scripts/
    │   ├── run.sh              # Container entrypoint (bootstrap + start)
    │   ├── gen_client.sh       # Create a named client + generate its cert
    │   ├── gen_client_cert.sh  # Generate Ed25519 cert for a client
    │   ├── gen_client_CA.sh    # Bootstrap the client CA
    │   ├── gen_server_cert.sh  # Generate server TLS cert
    │   ├── gen_server_CA.sh    # Bootstrap the server CA
    │   ├── bootstrap/          # ip_forward + rp_filter setup
    │   ├── postup/             # SNAT rules applied after VPN comes up
    │   └── predown/            # SNAT rule teardown before shutdown
    ├── extras/                 # OpenSSL .conf files for CA and cert requests
    ├── masqued.conf.template   # Server config template
    └── docker-compose.yml
```

---

## Requirements

**Server:** Linux, Docker, `NET_ADMIN` + `NET_RAW` capabilities, `/dev/net/tun`

**Client:** Linux (kernel TUN support), `NET_ADMIN` + `NET_RAW` capabilities

**Toolchain (build only):** Go 1.25+ (`golang:tip-alpine3.22` Docker image)

---

## Server setup

### 1. Prepare config

Copy the template and fill in your values:

```sh
cp server/masqued.conf.template server/masqued.conf
```

| Key | Required | Description | Example |
|-----|----------|-------------|---------|
| `LOG_LEVEL` | yes | Verbosity: `fatal`, `error`, `warn`, `info`, `debug`, `trace` | `info` |
| `LOG_PATH` | yes | Log file path | `/etc/masqued/log` |
| `WAN_INTERFACE` | yes | Host's WAN interface name | `eth0` |
| `BIND_ADDR` | yes | QUIC listener bind address | `0.0.0.0` |
| `LISTEN_PORT` | yes | QUIC listener port | `443` |
| `TUNNEL_IP` | yes | Server-side VPN tunnel IP (CIDR) | `10.76.0.1/31` |
| `TUNNEL_MTU` | no | TUN device MTU (default: 1416) | `1416` |
| `CLIENT_CIDR` | yes | DHCP pool for client IPs | `10.77.0.1/16` |
| `FILTER_IP_PROTOCOL` | yes | IP protocol filter (`0` = all) | `0` |
| `QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING` | yes | Suppress quic-go buffer warning | `true` |
| `QUIC_GO_DISABLE_GSO` | yes | Disable Generic Segmentation Offload | `true` |
| `SAN_DNS_LIST` | yes | Comma-separated DNS SANs for server cert | `vpn.example.com,*.example.com` |
| `SAN_IP_LIST` | yes | Comma-separated IP SANs for server cert | `1.2.3.4` |

### 2. Start the server

```sh
cd server
sudo docker compose up --build -d
```

On first boot, `run.sh` automatically:
1. Generates the server CA and server TLS certificate (Ed25519)
2. Generates the client CA
3. Runs database migrations (SQLite, schema v1)
4. Enables IP forwarding and disables reverse-path filtering
5. Starts `masqued` (the MASQUE daemon) and the management Unix socket

---

## Client setup

### 1. Provision a client on the server

Run this on the server (or via `docker compose exec`) with a name for the new client:

```sh
sudo docker compose exec masqued genClient alice
```

This registers `alice` in the database, generates an Ed25519 key pair signed by the client CA, and saves a `bundle.zip` to:

```
server/certs/client/alice/bundle.zip
```

The zip contains `client.crt`, `client.key`, and `ca.crt` (a symlink to the server CA).

> **Note:** `genClient` also automatically creates a role named `alice` and assigns it to the client. Use the management API to assign resources to that role to grant the client access to CIDR prefixes.

### 2. Copy certs to the client machine

```sh
# On the server
scp server/certs/client/alice/bundle.zip user@client-host:~

# On the client
mkdir -p /etc/masque/certs
cd /etc/masque/certs
unzip ~/bundle.zip
```

### 3. Configure the client

```sh
cp /path/to/masque.conf.template /etc/masque/masque.conf
```

Edit `/etc/masque/masque.conf`:

| Key | Required | Description | Example |
|-----|----------|-------------|---------|
| `LOG_LEVEL` | yes | Verbosity | `info` |
| `LOG_PATH` | yes | Log file path | `/etc/masque/logs/masque.log` |
| `ENABLE_KEY_LOG` | yes | Write TLS session keys (Wireshark) | `false` |
| `KEY_LOG_PATH` | yes | Path for TLS key log file | `/tmp/masque_keylog.txt` |
| `SERVER` | yes | Server address as `FQDN[:port]` (default port: 443) | `vpn.example.com:443` |
| `SERVER_CA_PATH` | yes | Path to server CA cert | `/etc/masque/certs/ca.crt` |
| `CLIENT_CERT_PATH` | yes | Path to client cert | `/etc/masque/certs/client.crt` |
| `CLIENT_KEY_PATH` | yes | Path to client private key | `/etc/masque/certs/client.key` |

### 4. Run the client

**Binary (bare metal / Alpine APK):**

```sh
sudo masque -f /etc/masque/masque.conf
```

**Docker:**

```sh
cd client
sudo docker compose up --build
```

The `docker-compose.yml` shows an example of two simultaneous clients (`client1`, `client2`) each with their own cert volume mount.

---

## Management API

The server (`masqued`) exposes an HTTP API over a Unix socket at `/var/run/masqued.sock`. All management tooling (including `genClient`) communicates through this socket. You can reach it directly with `curl --unix-socket`.

### Clients

| Method | Path | Body / Query | Description |
|--------|------|--------------|-------------|
| `GET` | `/client` | | List all clients |
| `POST` | `/client?type=upsert` | `{"names": ["alice"]}` | Create or update clients by name. Also auto-creates a same-named role and assigns it to each new client. Returns `{"ids": [...]}`. |
| `POST` | `/client?type=assign` | `{"client_ids": [...], "role_ids": [...]}` | Assign roles to clients |
| `POST` | `/client?type=unassign` | `{"client_ids": [...], "role_ids": [...]}` | Remove roles from clients |
| `DELETE` | `/client` | `{"ids": [...]}` | Delete clients by ID. Reclaims their IPs back into the DHCP pool. |
| `GET` | `/client/{id}` | | Get a specific client |
| `POST` | `/client/{id}` | `{"name": "new-name"}` | Rename a client |

### Roles

| Method | Path | Body / Query | Description |
|--------|------|--------------|-------------|
| `GET` | `/role` | | List all roles |
| `POST` | `/role?type=upsert` | `{"names": ["engineering"]}` | Create or update roles by name |
| `POST` | `/role?type=client` | `{"client_id": 1}` | List all roles assigned to a client |
| `POST` | `/role?type=assign` | `{"role_ids": [...], "resource_ids": [...]}` | Assign resources to roles |
| `POST` | `/role?type=unassign` | `{"role_ids": [...], "resource_ids": [...]}` | Remove resources from roles |
| `DELETE` | `/role` | `{"ids": [...]}` | Delete roles by ID |
| `GET` | `/role/{id}` | | Get a specific role |
| `POST` | `/role/{id}` | `{"name": "new-name"}` | Rename a role |

### Resources

Resources are CIDR prefixes that the server advertises as routes to any client holding a role that grants those resources.

| Method | Path | Body / Query | Description |
|--------|------|--------------|-------------|
| `GET` | `/resource` | | List all resources |
| `POST` | `/resource?type=upsert` | `{"resources": [{"name": "corp-net", "value": "10.0.0.0/8"}]}` | Create or update resources. `value` is the CIDR prefix. On name conflict, updates `value`. |
| `POST` | `/resource?type=client` | `{"client_id": 1}` | List all resources reachable by a client (via its roles) |
| `DELETE` | `/resource` | `{"ids": [...]}` | Delete resources by ID |
| `GET` | `/resource/{id}` | | Get a specific resource |
| `POST` | `/resource/{id}` | `{"name": "new-name"}` | Rename a resource |

### DHCP

| Method | Path | Body | Description |
|--------|------|------|-------------|
| `GET` | `/dhcp` | | Get the current available IP ranges |
| `PUT` | `/dhcp` | `{"fist_ip": <int>, "last_ip": <int>}` | Replace the IP pool (integer-encoded IPv4 addresses) |

### Examples

```sh
# Create client "alice" (also auto-creates and assigns role "alice")
curl --unix-socket /var/run/masqued.sock \
  -X POST 'http://masqued/client?type=upsert' \
  -d '{"names": ["alice"]}'
# → {"ids":[1]}

# List all clients
curl --unix-socket /var/run/masqued.sock http://masqued/client

# Create a resource (CIDR prefix)
curl --unix-socket /var/run/masqued.sock \
  -X POST 'http://masqued/resource?type=upsert' \
  -d '{"resources": [{"name": "corp-net", "value": "10.0.0.0/8"}]}'

# Assign resource 1 to role 1 (alice's auto-created role)
curl --unix-socket /var/run/masqued.sock \
  -X POST 'http://masqued/role?type=assign' \
  -d '{"role_ids": [1], "resource_ids": [1]}'

# Check what resources alice can reach
curl --unix-socket /var/run/masqued.sock \
  -X POST 'http://masqued/resource?type=client' \
  -d '{"client_id": 1}'

# Delete client 1
curl --unix-socket /var/run/masqued.sock \
  -X DELETE 'http://masqued/client' \
  -d '{"ids": [1]}'
```

---

## Access control model

```
Client ──(many-to-many)──► Role ──(many-to-many)──► Resource (CIDR prefix)
```

When a client connects, `masqued`:
1. Looks up the client's roles via the mTLS certificate CN (client DB ID)
2. Collects all resources (CIDR prefixes) associated with those roles
3. Advertises those prefixes as routes to the client via `CONNECT-IP`

A client with no roles assigned (or roles with no resources) receives no routes and cannot tunnel any traffic.

When a client is created via `genClient` or `POST /client?type=upsert`, a role with the same name is automatically created and assigned to it. This default role starts with no resources — assign CIDR resources to it to grant access.

---

## Certificate architecture

```
Server CA (Ed25519, 10yr)
  └── server.crt  (Ed25519, signed by Server CA)
          Used for: QUIC/TLS server authentication

Client CA (Ed25519, 10yr)
  └── client.crt  (Ed25519, signed by Client CA, CN = client DB ID)
          Used for: mTLS client authentication + client identity
```

The server trusts the Client CA and requires client certificates (`RequireAndVerifyClientCert`). The client trusts the Server CA. There is no cross-signing — the two CAs are independent.

## Security notes

- All keys are Ed25519. No RSA, no ECDSA.
- The `ENABLE_KEY_LOG` option writes TLS session keys to disk for Wireshark-based debugging. **Never enable this in production.**
- Raw sockets require `CAP_NET_ADMIN` and `CAP_NET_RAW`. The `masqued` binary has `cap_net_admin+ep` applied at runtime by `run.sh`.

---

## Troubleshooting

**`masque` fails to connect with `failed to dial QUIC connection`**
- Confirm port 443/UDP is open on the server firewall
- Confirm `SERVER` in `masque.conf` resolves to the correct IP
- Check that `ca.crt` on the client matches the server's CA

**Client connects but has no routes / no internet**
- The client may have no roles assigned, or the roles have no resources
- Use `genClient` and the management API to assign CIDR resources to the client's role

**`Failed to get available IP`**
- The DHCP pool may be exhausted
- Check the pool with `GET /dhcp` and expand it with `PUT /dhcp` if needed

**`setsockopt(SOL_SOCKET, SO_MARK) — process needs CAP_NET_ADMIN`**
- The `masqued` binary must have `CAP_NET_ADMIN`. In Docker this is provided by `cap_add: NET_ADMIN`. Bare-metal: `sudo setcap cap_net_admin+ep ./bin`
