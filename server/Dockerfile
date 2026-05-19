FROM ubuntu:24.04 as builder

WORKDIR /server
RUN apt-get update && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
    golang clang llvm libelf-dev libbpf-dev linux-headers-generic
RUN ln -sf /usr/include/$(uname -m)-linux-gnu/asm /usr/include/asm
COPY src /server/src
COPY lib /lib
COPY build.sh /server/build.sh
RUN chmod +x /server/build.sh && /server/build.sh

FROM ubuntu:24.04 as runner

RUN apt-get update && apt upgrade -y
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y \
        iproute2 iptables ethtool openssl sqlite3 curl jq zip

COPY ./*.conf /etc/masqued/
COPY extras /etc/masqued/extras
COPY scripts /etc/masqued/scripts
COPY --from=builder /server/build/bin /usr/sbin/masqued

RUN ln -s /etc/masqued/scripts/run.sh /run.sh

RUN chmod +x /run.sh
