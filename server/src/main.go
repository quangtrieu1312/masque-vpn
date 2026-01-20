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

    "gorm.io/driver/sqlite"
    "gorm.io/gorm"
)


var serverSocketSend int
var tunTapDevice *water.Interface
var db *gorm.DB
var mu sync.RWMutex
var ipToTunChan map[string](chan []byte)

func main() {
    ctx := context.WithoutCancel(context.Background())
    sigc := make(chan os.Signal, 1)
    signal.Notify(sigc,
        syscall.SIGHUP,
        syscall.SIGINT,
        syscall.SIGTERM,
        syscall.SIGQUIT)
    go func(ctxt *context.Context) {
        <-sigc
        GracefullyShutDown(ctxt)
    }(&ctx)

    ParseConfig(&ctx)
    logLevel := ctx.Value("LOG_LEVEL").(string)
    GetLoggerInstance()
    UpdateLogLevelName(logLevel)
    ifaceName := ctx.Value("WAN_INTERFACE").(string)
    bindAddr := netip.MustParseAddr(ctx.Value("BIND_ADDR").(string))
    listenPort, err := strconv.Atoi(ctx.Value("LISTEN_PORT").(string))

	if err != nil {
		LogFatal(fmt.Sprintf("Failed to parse proxy port: %v", err))
	}
	bindTo := netip.AddrPortFrom( bindAddr, uint16(listenPort))

	virtIp, virtSubnet, err := net.ParseCIDR(ctx.Value("TUNNEL_IP").(string))
	if err != nil {
		LogFatal(fmt.Sprintf("Failed to parse TUNNEL_IP: %v", err))
	}
	ipProtocol, err := strconv.ParseUint(ctx.Value("FILTER_IP_PROTOCOL").(string), 10, 8)
	if err != nil {
		LogFatal(fmt.Sprintf("failed to parse FILTER_IP_PROTOCOL: %v", err))
	}

	mtu, err := strconv.ParseUint(ctx.Value("TUNNEL_MTU").(string), 10, 64)
	if err != nil {
        mtu = 1416
        LogInfo(fmt.Sprintf("Tunnel MTU is set to default = %d", mtu))
    }
    link, err := netlink.LinkByName(ifaceName)
	if err != nil {
		LogFatal(fmt.Sprintf("failed to get %s interface: %v", ifaceName, err))
	}
	// assuming we are only doing IPv4
	family := netlink.FAMILY_V4
	addrs, err := netlink.AddrList(link, family)
	if err != nil {
		LogFatal(fmt.Sprintf("failed to get addresses for %s: %v", ifaceName, err))
	}
	if len(addrs) == 0 {
		LogFatal(fmt.Sprintf("no IP addresses found for %s", ifaceName))
	}
	var ethAddr netip.Addr
	for _, addr := range addrs {
		a, ok := netip.AddrFromSlice(addr.IP)
		if !ok {
			LogFatal(fmt.Sprintf("failed to parse %s address", ifaceName))
		}
		if !a.IsLinkLocalUnicast() {
			ethAddr = a
			break
		}
	}

	netBitSize, _ := virtSubnet.Mask.Size()
	dev, err := createTunTapDevice(ctx, virtIp.String(), netBitSize, int(mtu))
	if err != nil {
		LogFatal(fmt.Sprintf("failed to create tun/tap device: %v", err))
	}
    tunTapDevice = dev

	fdSnd, err := createSendSocket(ethAddr)
	if err != nil {
		LogFatal(fmt.Sprintf("failed to create send socket: %v", err))
	}
	serverSocketSend = fdSnd

	upChan := make(chan bool)
    go func(ctxt *context.Context) {
        for {
            isRunning := <- upChan
            if (isRunning) {
                PostUp(ctxt)
            } else {
                GracefullyShutDown(ctxt)
            }
        }
    }(&ctx)
    Bootstrap(&ctx)
	if err := run(ctx, upChan, bindTo, uint8(ipProtocol)); err != nil {
		LogFatal(fmt.Sprintf("%v",err))
	}
    LogInfo("Shutting down masque server.")
}


func Bootstrap(ctx *context.Context) {
    LogInfo("Server in bootstrap phase")
    cmd := exec.Command("/bin/bash", "-c", SCRIPT_DIR + "/bootstrap.sh")
    _, err := cmd.Output()
    if err != nil {
        LogFatal(fmt.Sprintf("Failed bootstrap scripts: %v", err))
    }

    db, err := gorm.Open(sqlite.Open(DB_PATH), &gorm.Config{})
    if err != nil {
        LogFatal("Failed to connect database")
    }
    // Migrate the schema
    db.AutoMigrate(&Client{})
    db.AutoMigrate(&Role{})
    db.AutoMigrate(&Resource{})
    db.AutoMigrate(&IP{})
    db.AutoMigrate(&DHCP{})
}

func PostUp(ctx *context.Context) {
    LogInfo("Server in post-up phase")
    cmd := exec.Command("/bin/bash", "-c", SCRIPT_DIR + "/postup.sh")
    _, err := cmd.Output()
    if err != nil {
        LogFatal(fmt.Sprintf("Cannot run postup scripts: %v", err))
    }
}

func PreDown() {
    LogInfo("Server in pre-down phase")
    cmd := exec.Command("/bin/bash", "-c", SCRIPT_DIR + "/predown.sh")
    _, err := cmd.Output()
    if err != nil {
        LogFatal(fmt.Sprintf("Cannot run predown scripts: %v", err))
    }
}

func GracefullyShutDown(ctx *context.Context) {
    LogInfo("Shutting down")
    PreDown()
    (*ctx).Done()
}

func createTunTapDevice(ctx context.Context, virtIp string, virtPrefixLen int, mtu int) (*water.Interface, error) {
	dev, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, fmt.Errorf("Failed to create TUN device: %w", err)
	}
	LogInfo(fmt.Sprintf("Created TUN device: %s", dev.Name()))

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
    clientIp, clientSubnet, err := net.ParseCIDR(ctx.Value("CLIENT_CIDR").(string))
    prefixAddr, err := netip.ParseAddr(clientIp.String())
    if err != nil {
        return  nil, fmt.Errorf("Failed to parse address: %w", err)
    }
    bitmask, _ := clientSubnet.Mask.Size()
    prefix := netip.PrefixFrom(prefixAddr, bitmask)
    route := &netlink.Route{ LinkIndex: link.Attrs().Index, Dst: PrefixToIPNet(prefix) }
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
    udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: bindTo.Addr().AsSlice(), Port: int(bindTo.Port())})
	if err != nil {
		return fmt.Errorf("Failed to listen on UDP: %w", err)
	}
	defer udpConn.Close()

	cert, err := tls.LoadX509KeyPair(SERVER_CERT_PATH, SERVER_KEY_PATH)
	if err != nil {
		return fmt.Errorf("Failed to load TLS certificate: %w", err)
	}
	certPool, err := x509.SystemCertPool()
    if err != nil {
		return fmt.Errorf("Cannot create cert pool: %w", err)
    }
    caCertPEM, err := os.ReadFile(CLIENT_CA_PATH)
    if err != nil {
        return fmt.Errorf("Cannot read client CA:", err)
	}
    ok := certPool.AppendCertsFromPEM(caCertPEM)
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
    ipToTunChan := make(map[string](chan []byte))
    mu := &sync.RWMutex{}
    go func() {
        for {
	        b := make([]byte, 1500)
	        n, err := tunTapDevice.Read(b)
			LogTrace(fmt.Sprintf("Unfiltered data %v: %x", tunTapDevice.Name(), b[:n]))
            if err != nil {
                LogError(fmt.Sprintf("Cannot read TUN/TAP device %v: %v", tunTapDevice.Name(), err))
                cancel()
                break
            } else {
                // assuming we are only doing IPv4
                destIP, ok := netip.AddrFromSlice(b[16:20])
                if ! ok {
				    LogTrace(fmt.Sprintf("Cannot parse data to IP. Dropping packet."))
                    continue
                }
				LogTrace(fmt.Sprintf("Dest IP to filter %v", destIP.String()))
                mu.RLock()
                if tunChan, ok := ipToTunChan[destIP.String()]; ok {
                	tunChan <- b[:n]
				} else {
                    LogTrace(fmt.Sprintf("Cannot find connection for client IP = %s. Dropping packet.", destIP.String()))
                }
                mu.RUnlock()
            }
        }
    }()
	mux.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
		LogDebug(fmt.Sprintf("Handle new HTTP client"))
        clientId := (*r.TLS.PeerCertificates[0]).Subject.CommonName
        conCtx := context.WithValue(ctx, "clientId", clientId)
        GetClientResources(&conCtx, db, clientId)
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

		if err := handleConn(conCtx, make(chan []byte), conn, ipProtocol); err != nil {
			LogError(fmt.Sprintf("failed to handle connection: %v", err))
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

func handleConn(contxt context.Context, tunChan chan []byte,  conn *connectip.Conn, ipProtocol uint8) error {
	ctx, cancel := context.WithTimeout(contxt, 5*time.Second)
	defer cancel()
    LogDebug("Start connectip flow")
    // Get the next unassigned address
    // And assign prefix = IP/32 to the client
    // Note:
    // We can assign any subnet size here but I'm using /32 for simplicity
    // I may want to go back to this hardcoded number when I see issues for site-to-side VPN
    clientId := ctx.Value("clientId").(string)
    peerAddr, perr := AssignIPToClient(&ctx, db, clientId)
    if perr != nil {
        return fmt.Errorf("Failed to get available IP: %w", perr)
    }
    addr, e := netip.ParseAddr(peerAddr)
    if e != nil {
        return fmt.Errorf("Failed to parse address: %w", e)
    }
    bitmask := 32
    ipPrefix := netip.PrefixFrom(addr, bitmask)
	if err := conn.AssignAddresses(ctx, []netip.Prefix{ipPrefix}); err != nil {
		return fmt.Errorf("failed to assign addresses: %w", err)
	}
    mu.Lock()
    ipToTunChan[peerAddr] = tunChan
    mu.Unlock()
    clientResources, cerr := GetClientResources(&ctx, db, clientId)
    if cerr != nil {
        return cerr
    }
    clientRoutes := []connectip.IPRoute{}
    for i := 0; i < len(clientResources); i++ {
        r, e := netip.ParsePrefix(clientResources[i].Value)
        if e != nil {
            continue
        }
        connectipRoute := connectip.IPRoute{StartIP: r.Addr(), EndIP: LastIP(r), IPProtocol: ipProtocol}
        clientRoutes = append(clientRoutes, connectipRoute)
    }
	if err := conn.AdvertiseRoute(ctx, clientRoutes); err != nil {
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
            LogTrace(fmt.Sprintf("QUIC -> WAN: read %d bytes, response payload = %x", n, b[:n]))
			if err := sendOnSocket(serverSocketSend, b[:n]); err != nil {
				errChan <- fmt.Errorf("writing to server socket: %w", err)
				return
			}
		}
	}()

	go func() {
		for {
            data := <-tunChan
            LogTrace(fmt.Sprintf("TUN -> QUIC: read %d bytes, response payload = %x", len(data), data))
			icmp, err := conn.WritePacket(data)
			if err != nil {
				errChan <- fmt.Errorf("failed to write to connection: %w", err)
				return
			}
			if len(icmp) > 0 {
				if err := sendOnSocket(serverSocketSend, icmp); err != nil {
					LogError(fmt.Sprintf("failed to send ICMP packet: %v", err))
                    return
				}
			}
		}
	}()

	err := <-errChan
	LogError(fmt.Sprintf("error proxying: %v", err))
	conn.Close()
	<-errChan // wait for the other goroutine to finish
	return err
}
