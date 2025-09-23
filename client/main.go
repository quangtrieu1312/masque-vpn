package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	connectip "github.com/quic-go/connect-ip-go"
	//"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"

	utils "github.com/quangtrieu1312/masque-vpn/client/utils"
)

var isDebugMode bool

func main() {
	proxyPort, err := strconv.Atoi("443")
	if err != nil {
		log.Fatalf("failed to parse proxy port: %v", err)
	}
    ips, err := net.LookupIP("amdl.iiiii.info")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not get IPs: %v\n", err)
		os.Exit(1)
	}
	proxyAddr := netip.AddrPortFrom(netip.MustParseAddr(ips[0].String()), uint16(proxyPort))
	if err != nil {
		log.Fatalf("failed to parse server URL: %v", err)
	}
    isDebugMode := false
	keyLog, err := os.Create("keys.txt")
	if err != nil {
		log.Fatalf("failed to create key log file: %v", err)
	}
	defer keyLog.Close()
	dev, ipconn, err := establishConn(proxyAddr, keyLog, isDebugMode)
	if err != nil {
		log.Fatalf("failed to establish connection: %v", err)
	}
	log.Printf("Created TUN device: %s in the background", dev.Name())
	proxy(ipconn, dev)
}

func establishConn(proxyAddr netip.AddrPort, keyLog io.Writer, isDebugMode bool) (*water.Interface, *connectip.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
    udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}
    /*
    fd, err := udpConn.SyscallConn()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create file descriptor on UDPConn: %w", err)
    }
    mark := 12345
    err = fd.Control(func(fd uintptr) {
        unix.SetsockoptInt(
            int(fd),
            unix.SOL_SOCKET,
            unix.SO_MARK,
            int(mark),
        )
	})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to change socket option: %w", err)
	} 
    */
    // load tls configuration
    CertFilePath := "/home/quangtrieu1312/repositories/masque-vpn/client/certs/client.crt"
    KeyFilePath := "/home/quangtrieu1312/repositories/masque-vpn/client/certs/client.key"
    CACertFilePath := "/home/quangtrieu1312/repositories/masque-vpn/client/certs/ca.crt"
	cert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
	if err != nil {
		panic(err)
	}
	// Configure the client to trust TLS server certs issued by a CA.
	certPool, err := x509.SystemCertPool()
	if err != nil {
		panic(err)
	}
	if caCertPEM, err := os.ReadFile(CACertFilePath); err != nil {
		panic(err)
	} else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		panic("invalid cert in CA PEM")
	}
    tlsConf :=  &tls.Config {
		ServerName:         "test",
		InsecureSkipVerify: true,
		NextProtos:         []string{http3.NextProtoH3},
        RootCAs:            certPool,
		Certificates:       []tls.Certificate{cert},
        KeyLogWriter:       keyLog,
    }
	conn, err := quic.Dial(
		ctx,
		udpConn,
		&net.UDPAddr{IP: proxyAddr.Addr().AsSlice(), Port: int(proxyAddr.Port())},
		tlsConf,
		&quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
		},
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	hconn := tr.NewClientConn(conn)

	template := uritemplate.MustNew(fmt.Sprintf("https://masque:%d/vpn", proxyAddr.Port()))
	ipconn, rsp, err := connectip.Dial(ctx, hconn, template)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}
	log.Printf("connected to VPN server: %s", proxyAddr)

	routes, err := ipconn.Routes(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get routes: %w", err)
	}
	localPrefixes, err := ipconn.LocalPrefixes(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get local prefixes: %w", err)
	}

	dev, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create TUN device: %w", err)
	}
	log.Printf("created TUN device: %s", dev.Name())

	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get TUN interface: %w", err)
	}
	for _, p := range localPrefixes {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: utils.PrefixToIPNet(p)}); err != nil {
			return nil, nil, fmt.Errorf("failed to add address assigned by peer %s: %w", p, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	for _, route := range routes {
		log.Printf("adding routes for %s - %s (protocol: %d)", route.StartIP, route.EndIP, route.IPProtocol)
		for _, prefix := range route.Prefixes() {
			r := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       utils.PrefixToIPNet(prefix),
			}
			if err := netlink.RouteAdd(r); err != nil {
				return nil, nil, fmt.Errorf("failed to add route: %w", err)
			}
		}
	}
	return dev, ipconn, nil
}

func proxy(ipconn *connectip.Conn, dev *water.Interface) error {
	log.Printf("Proxying")
	ctx, _ := context.WithTimeout(context.Background(), 5000*time.Second)
	go func() {
		for {
			b := make([]byte, 1500)
			n, rerr := ipconn.ReadPacket(b)
			for {
                if rerr != nil {
				    log.Printf("failed to read from connection: %w", rerr)
                    break
                } else {
                    break
                }
                n, rerr = ipconn.ReadPacket(b)
			}
            log.Printf("Read full %d bytes from connection: %x", n, b[:n])
            _, werr := dev.Write(b[:n])
            for {
                if werr != nil {
				    log.Printf("failed to write to TUN: %w", werr)
                    _, werr = dev.Write(b[:n])
                    break
                } else {
                    break
                }
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, 1500)
            n, rerr := dev.Read(b)
			for {
                if rerr != nil {
				    log.Printf("failed to read from TUN: %w", rerr)
                    n, rerr = dev.Read(b)
                    break
                } else {
                    break
                }
			}
			icmp, werr := ipconn.WritePacket(b[:n])
			for {
                if werr != nil {
				    log.Printf("failed to write to connection: %w", werr)
			        icmp, werr = ipconn.WritePacket(b[:n])
                    break
                } else {
                    break
                }
			}
			if len(icmp) > 0 {
				log.Printf("sending ICMP packet on %s", dev.Name())
				if _, err := dev.Write(icmp); err != nil {
					log.Printf("failed to write ICMP packet: %v", err)
				}
			}
		}
	}()
    <-ctx.Done()
	dev.Close()
	ipconn.Close()
	log.Printf("Exitting")
	return nil
}

func ipForURL(addr netip.Addr) string {
	if addr.Is4() {
		return addr.String()
	}
	return fmt.Sprintf("[%s]", addr)
}
