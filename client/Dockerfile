FROM golang:tip-alpine3.22 as builder
RUN mkdir -p /build /src
COPY src /src
WORKDIR /src
RUN go build -o /build/client

FROM alpine:latest as runner
WORKDIR /
COPY --from=builder /build/client /client
RUN mkdir -p /etc/masque/logs && touch /etc/masque/logs/masque.log
RUN chmod +x /client
CMD ["/client"]
