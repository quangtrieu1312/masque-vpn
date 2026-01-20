FROM ubuntu:24.04

RUN apt-get update -y && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        iproute2 iptables ethtool openssl sqlite3

COPY ./*.conf /opt/masqued/
COPY extras /opt/masqued/extras
COPY scripts /opt/masqued/scripts
COPY build/bin /opt/masqued/bin

RUN ln -s /opt/masqued/scripts/run.sh /run.sh

RUN chmod +x /run.sh
