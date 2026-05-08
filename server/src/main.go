//go:build linux

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"sync"
	"time"
	"os/exec"
	"os/signal"
    "syscall"

	"golang.org/x/sys/unix"

	connectip "github.com/quic-go/connect-ip-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"

    "github.com/quangtrieu1312/masque-vpn/server/constants"
    "github.com/quangtrieu1312/masque-vpn/server/utility"
    "github.com/quangtrieu1312/masque-vpn/server/db"
    "github.com/quangtrieu1312/masque-vpn/server/config"
    "github.com/quangtrieu1312/masque-vpn/server/logger"
    "github.com/quangtrieu1312/masque-vpn/server/migration"
    "github.com/quangtrieu1312/masque-vpn/server/service"
)

var tunTapDevice *water.Interface
var mu *sync.RWMutex
var ipToTunChan map[string](chan []byte)
var wanAddr netip.Addr

func main() {
    ctx := context.WithoutCancel(context.Background())
    sigc := make(chan os.Signal, 1)
    signal.Notify(sigc,
        syscall.SIGHUP,
        syscall.SIGINT,
        syscall.SIGTERM,
        syscall.SIGQUIT)
    go func(ctxt context.Context) {
        <-sigc
        RunPreDown()
        GracefullyShutDown(ctxt)
    }(ctx)

    config.Load(&ctx)
    logLevel := ctx.Value("LOG_LEVEL").(string)
    logPath := ctx.Value("LOG_PATH").(string)
    logger.UpdateLogLevelName(logLevel)
    logger.UpdateLogPath(logPath)
    ifaceName := ctx.Value("WAN_INTERFACE").(string)
    bindAddr := netip.MustParseAddr(ctx.Value("BIND_ADDR").(string))
    listenPort, err := strconv.Atoi(ctx.Value("LISTEN_PORT").(string))

	if err != nil {
		logger.Fatal(fmt.Sprintf("Failed to parse proxy port: %v", err))
	}
	bindTo := netip.AddrPortFrom( bindAddr, uint16(listenPort))

	virtIp, virtSubnet, err := net.ParseCIDR(ctx.Value("TUNNEL_IP").(string))
	if err != nil {
		logger.Fatal(fmt.Sprintf("Failed to parse TUNNEL_IP: %v", err))
	}
	ipProtocol, err := strconv.ParseUint(ctx.Value("FILTER_IP_PROTOCOL").(string), 10, 8)
	if err != nil {
		logger.Fatal(fmt.Sprintf("failed to parse FILTER_IP_PROTOCOL: %v", err))
	}

	mtu, err := strconv.ParseUint(ctx.Value("TUNNEL_MTU").(string), 10, 64)
	if err != nil {
        mtu = 1416
        logger.Info(fmt.Sprintf("Tunnel MTU is set to default = %d", mtu))
    }
    link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		logger.Fatal(fmt.Sprintf("failed to get %s interface: %v", ifaceName, err))
	}
	// assuming we are only doing IPv4
	family := netlink.FAMILY_V4
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		logger.Fatal(fmt.Sprintf("failed to get addresses for %s: %v", ifaceName, err))
	}
	if len(addrs) == 0 {
		logger.Fatal(fmt.Sprintf("no IP addresses found for %s", ifaceName))
	}
	for _, addr := range addrs {
		a, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			logger.Fatal(fmt.Sprintf("failed to parse %s address", ifaceName))
		}
		if !a.IsLinkLocalUnicast() {
			wanAddr = a
			break
		}
	}

	netBitSize, _ := virtSubnet.Mask.Size()
	dev, err := createTunTapDevice(ctx, virtIp.String(), netBitSize, int(mtu))
	if err != nil {
		logger.Fatal(fmt.Sprintf("failed to create tun/tap device: %v", err))
	}
    tunTapDevice = dev

	upChan := make(chan bool)
    go func(ctxt context.Context) {
        for {
            isRunning := <- upChan
            if (isRunning) {
                RunPostUp(ctxt)
            } else {
                GracefullyShutDown(ctxt)
            }
        }
    }(ctx)
    Bootstrap(ctx)
	if err := run(ctx, upChan, bindTo, uint8(ipProtocol)); err != nil {
		logger.Fatal(fmt.Sprintf("%v",err))
	}
    logger.Info("Shutting down masque server.")
}


func Bootstrap(ctx context.Context) {
    logger.Info("Server in bootstrap phase")
    cmd := exec.Command("/bin/bash", "-c", constants.BOOTSTRAP_SCRIPT_PATH)
    _, err := cmd.Output()
    if err != nil {
        logger.Fatal(fmt.Sprintf("Failed bootstrap scripts: %v", err))
    }
    MigrateData(ctx)
}

func MigrateData(ctx context.Context) {
    // Migrate the schema
    logger.Info("Migrating data")
    migration.Invoke(ctx)
}

func RunPostUp(ctx context.Context) {
    logger.Info("Server in post-up phase")
    cmd := exec.Command("/bin/bash", "-c", constants.POSTUP_SCRIPT_PATH)
    _, err := cmd.Output()
    if err != nil {
        logger.Fatal(fmt.Sprintf("Cannot run postup scripts: %v", err))
    }
    RunManagementService(ctx)
}

func RunPreDown() {
    logger.Info("Server in pre-down phase")
    cmd := exec.Command("/bin/bash", "-c", constants.PREDOWN_SCRIPT_PATH)
    _, err := cmd.Output()
    if err != nil {
        logger.Fatal(fmt.Sprintf("Cannot run predown scripts: %v", err))
    }
}

func GracefullyShutDown(ctx context.Context) {
    logger.Info("Shutting down")
    db.CloseConnection()
}

func createTunTapDevice(ctx context.Context, virtIp string, virtPrefixLen int, mtu int) (*water.Interface, error) {
	dev, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, fmt.Errorf("Failed to create TUN device: %w", err)
	}
	logger.Info(fmt.Sprintf("Created TUN device: %s", dev.Name()))

	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		return nil, fmt.Errorf("Failed to get TUN interface: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}
    addr, err := netlink.ParseAddr(virtIp + "/" + strconv.Itoa(virtPrefixLen))
    if err != nil {
        return nil, fmt.Errorf("Failed to assign IP to %v: %v", dev.Name(), err)
    }
    netlink.AddrAdd(link, addr)
    netlink.LinkSetMTU(link, mtu)
    _, clientSubnet, err := net.ParseCIDR(ctx.Value("CLIENT_CIDR").(string))
    if err != nil {
        return  nil, fmt.Errorf("Failed to parse address: %w", err)
    }
    ip := clientSubnet.IP.String()
    bitmask, _ := clientSubnet.Mask.Size()
    prefixAddr, err := netip.ParsePrefix(ip + "/" + strconv.Itoa(bitmask))
    if err != nil {
        return  nil, fmt.Errorf("Failed to parse prefix: %w", err)
    }
    route := &netlink.Route{ LinkIndex: link.Attrs().Index, Dst: utility.PrefixToIPNet(prefixAddr) }
	if err := netlink.RouteAdd(route); err != nil {
		return nil, fmt.Errorf("Failed to add route %v: %w", route, err)
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
		return 0, fmt.Errorf("Creating socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return 0, fmt.Errorf("Setting IP_HDRINCL: %w", err)
	}
    sa := &unix.SockaddrInet4{Port: 0} // raw sockets don't use ports
    copy(sa.Addr[:], addr.AsSlice())
    if err := unix.Bind(fd, sa); err != nil {
        return 0, fmt.Errorf("Binding socket ipv4 to %s: %w", addr, err)
    }
	return fd, nil
}

func createSendSocketIPv6(addr netip.Addr) (int, error) {
	fd, err := unix.Socket(unix.AF_INET6, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return 0, fmt.Errorf("Creating socket: %w", err)
	}
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_HDRINCL, 1); err != nil {
		return 0, fmt.Errorf("Setting IPV6_HDRINCL: %w", err)
	}
    sa := &unix.SockaddrInet6{Port: 0} // raw sockets don't use ports
    copy(sa.Addr[:], addr.AsSlice())
    if err := unix.Bind(fd, sa); err != nil {
        return 0, fmt.Errorf("Binding socket ipv6 to %s: %w", addr, err)
    }
	return fd, nil
}

func htons(host uint16) uint16 {
	return (host<<8)&0xff00 | (host>>8)&0xff
}

func run(ctxt context.Context, upChan chan<- bool, bindTo netip.AddrPort, ipProtocol uint8) error {
    ctx, cancel := context.WithCancel(ctxt)
    defer cancel()
	mark := 31289
	lc := net.ListenConfig{
		Control: func(network, addr string, c syscall.RawConn) error {
			var soErr error
			err := c.Control(func(fd uintptr) {
				soErr = unix.SetsockoptInt(
					int(fd),
					unix.SOL_SOCKET, // level  : socket layer
					unix.SO_MARK,    // optname: SO_MARK
					mark,            // optval : 51820
				)
			})
			if err != nil {
				return fmt.Errorf("RawConn.Control: %w", err)
			}
			if soErr != nil {
				return fmt.Errorf("setsockopt(SOL_SOCKET, SO_MARK, %d): %w"+
					" — process needs CAP_NET_ADMIN", mark, soErr)
			}
			return nil
		},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", fmt.Sprintf("%v:%d",bindTo.Addr().String(), bindTo.Port()))
	if err != nil {
		return fmt.Errorf("Failed to listen on UDP: %w", err)
	}
	defer pc.Close()
 
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		return fmt.Errorf("expected *net.UDPConn, got %T", pc)
	}
	defer udpConn.Close()

	cert, err := tls.LoadX509KeyPair(constants.SERVER_CERT_PATH, constants.SERVER_KEY_PATH)
	if err != nil {
		return fmt.Errorf("Failed to load TLS certificate: %w", err)
	}
	certPool, err := x509.SystemCertPool()
    if err != nil {
		return fmt.Errorf("Cannot create cert pool: %w", err)
    }
    caCertPEM, err := os.ReadFile(constants.CLIENT_CA_PATH)
    if err != nil {
        return fmt.Errorf("Cannot read client CA:", err)
	}
    ok = certPool.AppendCertsFromPEM(caCertPEM)
    if !ok {
		return fmt.Errorf("Invalid cert")
	}
	template := uritemplate.MustNew(fmt.Sprintf("https://masque:%d/vpn", bindTo.Port()))
	serverConf := &tls.Config{
	    Certificates:          []tls.Certificate{cert},
	    ClientAuth:            tls.RequireAndVerifyClientCert,
	    ClientCAs:             certPool,
	}
    ln, err := quic.ListenEarly(
		udpConn,
		http3.ConfigureTLSConfig(serverConf),
		&quic.Config{
            EnableDatagrams: true,
            MaxIdleTimeout: 30*time.Second,
        },
	)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}
	defer ln.Close()

	p := connectip.Proxy{}
	mux := http.NewServeMux()
    ipToTunChan = make(map[string](chan []byte))
    mu = &sync.RWMutex{}
    go func() {
        for {
	        b := make([]byte, 1500)
	        n, err := tunTapDevice.Read(b)
			logger.Trace(fmt.Sprintf("Unfiltered data %v: %x", tunTapDevice.Name(), b[:n]))
            if err != nil {
                logger.Error(fmt.Sprintf("Cannot read TUN/TAP device %v: %v", tunTapDevice.Name(), err))
                cancel()
                break
            } else {
                // assuming we are only doing IPv4
                destIP, ok := netip.AddrFromSlice(b[16:20])
                if ! ok {
				    logger.Trace(fmt.Sprintf("Cannot parse data to IP. Dropping packet."))
                    continue
                }
				logger.Trace(fmt.Sprintf("Dest IP to filter %v", destIP.String()))
                mu.RLock()
                tunChan, ok := ipToTunChan[destIP.String()]
                mu.RUnlock()
				if ok {
                	pkt := make([]byte, n)
    				copy(pkt, b[:n])
    				select {
    					case tunChan <- pkt:
    					default:
        					logger.Trace(fmt.Sprintf("Client %s channel full, dropping packet.", destIP.String()))
    				}
				} else {
                    logger.Trace(fmt.Sprintf("Cannot find connection for client IP = %s. Dropping packet.", destIP.String()))
                }
            }
        }
    }()
	mux.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
        commonName := r.TLS.PeerCertificates[0].Subject.CommonName
    	clientId, err := strconv.ParseInt(commonName, 10, 64)
		if err != nil {
			logger.Info(fmt.Sprintf("Got invalid TLS common name %v: %v", commonName, err))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		logger.Debug(fmt.Sprintf("Handle new HTTP client %v", clientId))
        conCtx := context.WithValue(ctx, "clientId", clientId)
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
		fdSnd, err := createSendSocket(wanAddr)
		if err != nil {
			logger.Fatal(fmt.Sprintf("failed to create send socket: %v", err))
		}

		if err := handleConn(&conCtx, make(chan []byte, 256), conn, ipProtocol, fdSnd); err != nil {
			logger.Error(fmt.Sprintf("failed to handle connection: %v", err))
			return
		}
	})

	s := http3.Server{
		Handler:         mux,
		EnableDatagrams: true,
	}
	upChan <- true
	go s.ServeListener(ln)
	defer s.Close()
	<-ctx.Done()
	upChan <- false
	return nil
}

func handleConn(ctx *context.Context, tunChan chan []byte,  conn *connectip.Conn, ipProtocol uint8, fd int) error {
	setupCtx, setupCancel := context.WithTimeout(*ctx, 5*time.Second)
	defer setupCancel()
    logger.Debug("Start connectip flow")
    // Get the next unassigned address
    // And assign prefix = IP/32 to the client
    // Note:
    // We can assign any subnet size here but I'm using /32 for simplicity
    // I may want to go back to this hardcoded number when I see issues for site-to-side VPN
    clientId := (*ctx).Value("clientId").(int64)
    peerAddr, perr := service.AssignIPToClient(setupCtx, clientId)
    if perr != nil {
        return fmt.Errorf("Failed to get available IP: %w", perr)
    }
    addr, e := netip.ParseAddr(peerAddr)
    if e != nil {
        return fmt.Errorf("Failed to parse address: %w", e)
    }
    bitmask := 32
    ipPrefix := netip.PrefixFrom(addr, bitmask)
	if err := conn.AssignAddresses(setupCtx, []netip.Prefix{ipPrefix}); err != nil {
		return fmt.Errorf("failed to assign addresses: %w", err)
	}
    mu.Lock()
    ipToTunChan[peerAddr] = tunChan
    mu.Unlock()
    clientResources, cerr := service.GetClientResources(setupCtx, clientId)
    if cerr != nil {
        return cerr
    }
    clientRoutes := []connectip.IPRoute{}
    for i := 0; i < len(*clientResources); i++ {
        r, e := netip.ParsePrefix((*clientResources)[i].Value)
        if e != nil {
            continue
        }
        connectipRoute := connectip.IPRoute{StartIP: r.Addr(), EndIP: utility.LastIPAddr(r), IPProtocol: ipProtocol}
        clientRoutes = append(clientRoutes, connectipRoute)
    }
	if err := conn.AdvertiseRoute(setupCtx, clientRoutes); err != nil {
		return fmt.Errorf("failed to advertise route: %w", err)
	}

	errChan := make(chan error, 2)
	go func() {
		for {
			b := make([]byte, 1500)
			n, err := conn.ReadPacket(b)
			if err != nil {
				errChan <- fmt.Errorf("failed to read from MASQUE connection: %w", err)
				return
			}
            logger.Trace(fmt.Sprintf("TUN -> WAN: read %d bytes, response payload = %x", n, b[:n]))
			if err := utility.SendOnSocket(fd, b[:n]); err != nil {
				errChan <- fmt.Errorf("writing to server socket: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
            data := <-tunChan
			logger.Debug(fmt.Sprintf("tunChan len=%d cap=256 for client %s", len(tunChan), peerAddr))
            logger.Trace(fmt.Sprintf("WAN -> TUN: read %d bytes, response payload = %x", len(data), data))
			icmp, err := conn.WritePacket(data)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
        			errChan <- err  // fatal, connection is gone
        			return
    			}
				// maybe the packet queue is just full
				// as a VPN server we drop packet
				// and transportation layer (L4) can retry
				errChan <- fmt.Errorf("failed to write to MASQUE connection, drop packet: %w", err)
			}
			if len(icmp) > 0 {
				if err := utility.SendOnSocket(fd, icmp); err != nil {
					logger.Error(fmt.Sprintf("failed to send ICMP packet: %v", err))
				}
			}
		}
	}()

	err := <-errChan
	logger.Error(fmt.Sprintf("error proxying: %v", err))
	mu.Lock()
	delete(ipToTunChan, peerAddr)
	mu.Unlock()
	conn.Close()
	<-errChan // wait for the other goroutine to finish
	unix.Close(fd)
	return err
}
