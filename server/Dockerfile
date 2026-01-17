FROM ubuntu:24.04

RUN apt-get update -y && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        iproute2 iptables ethtool openssl sqlite3

COPY config /opt/masque/config
COPY scripts /opt/masque/scripts
COPY build/server /opt/masque/bin/masque-server

RUN ln -s /opt/masque/scripts/run.sh /run.sh

RUN chmod +x /run.sh
