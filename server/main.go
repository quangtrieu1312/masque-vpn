//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"

	connectip "github.com/quic-go/connect-ip-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"

    utils "github.com/quangtrieu1312/masque-vpn/server/utils"
)

var serverSocketSend int
var tunTapDevice *water.Interface


func main() {
    ifaceName := os.Getenv("SERVER_INTERFACE")
    bindAddr := netip.MustParseAddr(os.Getenv("BIND_ADDR"))
    listenPort, err := strconv.Atoi(os.Getenv("LISTEN_PORT"))

	if err != nil {
		log.Fatalf("failed to parse proxy port: %v", err)
	}
	bindTo := netip.AddrPortFrom( bindAddr, uint16(listenPort))

	assignAddr := netip.MustParsePrefix(os.Getenv("ASSIGN_ADDR"))
	route := netip.MustParsePrefix(os.Getenv("ROUTE"))
	ipProtocol, err := strconv.ParseUint(os.Getenv("FILTER_IP_PROTOCOL"), 10, 8)
	if err != nil {
		log.Fatalf("failed to parse FILTER_IP_PROTOCOL: %v", err)
	}

	link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		log.Fatalf("failed to get %s interface: %v", ifaceName, err)
	}
	family := netlink.FAMILY_V4
	if assignAddr.Addr().Is6() {
		family = netlink.FAMILY_V6
	}
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		log.Fatalf("failed to get addresses for %s: %v", ifaceName, err)
	}
	if len(addrs) == 0 {
		log.Fatalf("no IP addresses found for %s", ifaceName)
	}
	var ethAddr netip.Addr
	for _, addr := range addrs {
		a, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			log.Fatalf("failed to parse %s address", ifaceName)
		}
		if !a.IsLinkLocalUnicast() {
			ethAddr = a
			break
		}
	}

	dev, err := createTunTapDevice()
	if err != nil {
		log.Fatalf("failed to create tun/tap device: %v", err)
	}
	tunTapDevice = dev

	fdSnd, err := createSendSocket(ethAddr)
	if err != nil {
		log.Fatalf("failed to create send socket: %v", err)
	}
	serverSocketSend = fdSnd

    serverCertPath := os.Getenv("SERVER_CERT_PATH")
    serverKeyPath := os.Getenv("SERVER_KEY_PATH")
    clientCAPath := os.Getenv("CLIENT_CA_PATH")
	if err := run(bindTo, assignAddr, route, uint8(ipProtocol), serverCertPath, serverKeyPath, clientCAPath); err != nil {
		log.Fatal(err)
	}
}

func createTunTapDevice() (*water.Interface, error) {
	//ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	//defer cancel()

	dev, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}
	log.Printf("created TUN device: %s", dev.Name())

	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to get TUN interface: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}
	return dev, nil
}

func createSendSocket(addr netip.Addr) (int, error) {
	if addr.Is4() {
        return createSendSocketIPv4(addr)
    }
	return createSendSocketIPv6(addr)
}

func createSendSocketIPv4(addr netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return 0, fmt.Errorf("creating socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return 0, fmt.Errorf("setting IP_HDRINCL: %w", err)
	}
    sa := &unix.SockaddrInet4{Port: 0} // raw sockets don't use ports
    copy(sa.Addr[:], addr.AsSlice())
    if err := unix.Bind(fd, sa); err != nil {
        return 0, fmt.Errorf("binding socket ipv4 to %s: %w", addr, err)
    }
	return fd, nil
}

func createSendSocketIPv6(addr netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return 0, fmt.Errorf("creating socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		return 0, fmt.Errorf("setting IPV6_HDRINCL: %w", err)
	}
    sa := &unix.SockaddrInet6{Port: 0} // raw sockets don't use ports
    copy(sa.Addr[:], addr.AsSlice())
    if err := unix.Bind(fd, sa); err != nil {
        return 0, fmt.Errorf("binding socket ipv6 to %s: %w", addr, err)
    }
	return fd, nil
}

func htons(host uint16) uint16 {
	return (host<<8)&0xff00 | (host>>8)&0xff
}

func run(bindTo netip.AddrPort, remoteAddr netip.Prefix, route netip.Prefix, ipProtocol uint8, serverCertPath string, serverKeyPath string, clientCAPath string) error {
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindTo.Addr().AsSlice(), Port: int(bindTo.Port())})
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer udpConn.Close()

	cert, err := tls.LoadX509KeyPair(serverCertPath, serverKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}
	certPool, err := x509.SystemCertPool()
    if err != nil {
        panic(err)
    }
    caCertPEM, err := os.ReadFile(clientCAPath)
    if err != nil {
		panic(err)
	}
    ok := certPool.AppendCertsFromPEM(caCertPEM)
    if !ok {
		panic("invalid cert in CA PEM")
	}
	template := uritemplate.MustNew(fmt.Sprintf("https://masque:%d/vpn", bindTo.Port()))
	ln, err := quic.ListenEarly(
		udpConn,
		http3.ConfigureTLSConfig(&tls.Config{ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: certPool, Certificates: []tls.Certificate{cert}}),
		&quic.Config{EnableDatagrams: true},
	)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}
	defer ln.Close()

	p := connectip.Proxy{}
	mux := http.NewServeMux()
	mux.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
		req, err := connectip.ParseRequest(r, template)
		if err != nil {
			var perr *connectip.RequestParseError
			if errors.As(err, &perr) {
				w.WriteHeader(perr.HTTPStatus)
				return
			}
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		conn, err := p.Proxy(w, req)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		if err := handleConn(conn, remoteAddr, route, ipProtocol); err != nil {
			log.Printf("failed to handle connection: %v", err)
		}
	})
	s := http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
	}
	go s.ServeListener(ln)
	defer s.Close()

	select {}
}

func handleConn(conn *connectip.Conn, addr netip.Prefix, route netip.Prefix, ipProtocol uint8) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := conn.AssignAddresses(ctx, []netip.Prefix{netip.PrefixFrom(addr.Addr(), addr.Bits())}); err != nil {
		return fmt.Errorf("failed to assign addresses: %w", err)
	}
	if err := conn.AdvertiseRoute(ctx, []connectip.IPRoute{
		{StartIP: route.Addr(), EndIP: utils.LastIP(route), IPProtocol: ipProtocol},
	}); err != nil {
		return fmt.Errorf("failed to advertise route: %w", err)
	}

	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, 1500)
			n, err := conn.ReadPacket(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from connection: %w", err)
				return
			}
			if err := sendOnSocket(serverSocketSend, b[:n]); err != nil {
				errChan <- fmt.Errorf("writing to server socket: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
			b := make([]byte, 1500)
			n, err := tunTapDevice.Read(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from tun/tap device: %w", err)
				return
			}
			log.Printf("read %d bytes, response payload = %x", n, b[:n])
			icmp, err := conn.WritePacket(b[:n])
			if err != nil {
				errChan <- fmt.Errorf("failed to write to connection: %w", err)
				return
			}
			if len(icmp) > 0 {
				if err := sendOnSocket(serverSocketSend, icmp); err != nil {
					log.Printf("failed to send ICMP packet: %v", err)
				}
			}
		}
	}()

	err := <-errChan
	log.Printf("error proxying: %v", err)
	conn.Close()
	<-errChan // wait for the other goroutine to finish
	return err
}
