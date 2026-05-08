FROM ubuntu:24.04

RUN apt-get update -y && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        iproute2 iptables ethtool openssl sqlite3 curl jq zip

COPY ./*.conf /etc/masqued/
COPY extras /etc/masqued/extras
COPY scripts /etc/masqued/scripts
COPY build/bin /etc/masqued/bin

RUN ln -s /etc/masqued/scripts/run.sh /run.sh

RUN chmod +x /run.sh
