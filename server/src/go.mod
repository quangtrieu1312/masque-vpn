module github.com/quangtrieu1312/masque-vpn/server

go 1.25.0

require (
	github.com/asavie/xdp v0.3.3
	github.com/cilium/ebpf v0.21.0
	github.com/mattn/go-sqlite3 v1.14.33
	github.com/praserx/ipconv v1.2.2
	github.com/quic-go/connect-ip-go v0.1.0
	github.com/quic-go/quic-go v0.59.0
	github.com/slavc/xdp v0.3.4
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/vishvananda/netlink v1.3.0
	github.com/yosida95/uritemplate/v3 v3.0.2
	golang.org/x/net v0.48.0
	golang.org/x/sys v0.44.0
)

replace github.com/quic-go/connect-ip-go => ../../lib/connect-ip-go

replace github.com/quic-go/quic-go => ../../lib/quic-go

require (
	github.com/dunglas/httpsfv v1.0.2 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/vishvananda/netns v0.0.4 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/text v0.33.0 // indirect
)
