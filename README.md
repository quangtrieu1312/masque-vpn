# ABOUT
MASQUE is a tunneling protocol that runs on top of HTTP3/QUIC
The current implementation support IP over HTTP

# HOW TO RUN
## Server
Step 1: create an `.env` file

| Variable name | Required | Description   | Default value | Example |
| ------------- | -------- | ------------- | ------------- | ------- |
| LOG_LEVEL | Yes | The verbosity for logs | N/A | info |
| WAN_INTERFACE | Yes | WAN interface of the server | N/A | eth0 |
| BIND_ADDR | Yes | Bind address for QUIC server | N/A | 0.0.0.0 |
| LISTEN_PORT | Yes | Bind port for QUIC server | N/A | 443 |
| VIRTUAL_IP | Yes | Server address for VPN interface | N/A | 10.1.0.1/31 |
| CLIENT_CIDR | Yes | Client addresses for VPN interface | N/A | 10.2.0.1/16 |
| CLIENT_ROUTE | Yes | Client traffic for this route go through VPN tunnel | N/A | 8.8.4.4/32 |
| FILTER_IP_PROTOCOL | Yes | Protocol number that VPN server allows, `0` means all | N/A | 0 |
| QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING | Yes | Not sure what it does, but this is for a library | N/A | true |
| QUIC_GO_DISABLE_GSO | Yes | Same as the above | N/A | true |
| SERVER_CA_DIR | Yes | Server CA directory | N/A | /ca/server |
| CLIENT_CA_DIR | Yes | Client CA directory | N/A | /ca/client |
| SERVER_CERT_DIR | Yes | Server certs directory | N/A | /certs/server |
| CLIENT_CERT_DIR | Yes | Client certs directory | N/A | /certs/client |
| SAN_DNS_LIST | Yes | x509 dns SAN for server cert | N/A | example.com,*.example.com |
| SAN_IP_LIST | Yes | x509 ip SAN for server cert | N/A | 1.1.1.1,8.8.4.4,8.8.8.8 |

Step 2: Start the service
`sudo docker compose up --build -d`

## Client
### Linux
Step 1: Create local folder `/etc/masque/certs` and `/etc/masque/logs`

Step 2: Copy `client/config/masque0.conf.template` to `/etc/masque/masque0.conf`

| Variable name | Required | Description   | Default value | Example |
| ------------- | -------- | ------------- | ------------- | ------- |
| LOG_LEVEL | Yes | Verbosity for logs | N/A | info |
| LOG_PATH | Yes | Log path | N/A | /etc/masque/logs/masque.log |
| ENABLE_KEY_LOG | Yes | Log TLS key for decryption | N/A | false |
| KEY_LOG_PATH | Yes | Path for TLS key | N/A | /tmp/masque_keylog.txt |
| SERVER | Yes | MASQUE server in format `FQDN[:port]`, by default port is `443` | N/A | 1.2.3.4:567 |
| SERVER_CA_PATH | Yes | Path to server CA | N/A | /etc/masque/certs/ca.crt |
| CLIENT_CERT_PATH | Yes | Path to client cert | N/A | /etc/masque/certs/client.crt |
| CLIENT_KEY_PATH | Yes | Path to client key | N/A | /etc/masque/certs/client.key |
| BIDIRECTION | No | TBD | N/A | false |
| BIDIRECTION_ALLOW_SOURCE | No | TBD | N/A | 1.1.1.1/8,10.10.10.10/20 |
| BIDIRECTION_ALLOW_DEST | No | TBD | N/A | 1.1.1.1/8,10.10.10.10/20 |


Step 3: Go to MASQUE server and generate client cert with the helper script `genClientCert.sh`
`sudo docker compose exec -it masque-server /scripts/genClientCert.sh [client-name]`
A new RSA key pair with a x509 cert should be available in the mounted folder: `server/certs/client/` 

Step 4: Copy certs to client local folder `/etc/masque/certs`

Step 5: Build the binary `bash client/build.sh`

Step 6: Run the binary `sudo client/build/client`

### MacOS
WIP

### Windows
WIP
