FROM ubuntu:24.04

RUN apt-get update -y && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        iproute2 iptables ethtool openssl

COPY config /config
COPY scripts /scripts
COPY build/server /

RUN ln -s /scripts/run.sh /run.sh

RUN chmod +x /run.sh
