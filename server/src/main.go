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
    "runtime"
	_ "net/http/pprof"

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
type packet struct {
    buf []byte
    n   int
}
var packetPool = sync.Pool{
    New: func() any {
        return &packet{buf: make([]byte, 1500)}
    },
}
var tunTapDevice []*water.Interface
var mu *sync.RWMutex
var ipToTunChan map[netip.Addr](chan *packet)
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
	devs, err := createTunTapDevice(ctx, virtIp.String(), netBitSize, int(mtu))
	if err != nil {
		logger.Fatal(fmt.Sprintf("failed to create tun/tap device: %v", err))
	}
    tunTapDevice = devs

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
	go func(contxt context.Context) {
    	RunManagementService(contxt)
	}(ctx)
	go http.ListenAndServe("localhost:6060", nil)
	go func() {
    	t := time.NewTicker(5 * time.Second)
    	for range t.C {
        	f, p, avg := utility.BatchStats()
        	logger.Info(fmt.Sprintf("sendmmsg stats: flushes=%d packets=%d avg_batch=%.2f", f, p, avg))
    	}
	}()
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

func createTunTapDevice(ctx context.Context, virtIp string, virtPrefixLen int, mtu int) ([]*water.Interface, error) {
    numQueues := runtime.NumCPU()
    devs := make([]*water.Interface, numQueues)

	// First device — let OS assign name
	var err error
	devs[0], err = water.New(water.Config{
    	DeviceType: water.TUN,
    	PlatformSpecificParams: water.PlatformSpecificParams{
        	MultiQueue: true,
    	},
	})
	if err != nil {
    	return nil, fmt.Errorf("failed to create TUN device queue 0: %w", err)
	}
	devName := devs[0].Name()
	logger.Info(fmt.Sprintf("Created TUN device: %s", devName))
	// Subsequent queues — MUST use same name
	for i := 1; i < numQueues; i++ {
    	dev, err := water.New(water.Config{
        	DeviceType: water.TUN,
        	PlatformSpecificParams: water.PlatformSpecificParams{
            	Name:       devName, // same device, new fd
            	MultiQueue: true,
        	},
    	})
    	if err != nil {
        	return nil, fmt.Errorf("failed to create TUN queue %d: %w", i, err)
    	}
    	devs[i] = dev
	}

	link, err := netlink.LinkByName(devs[0].Name())
	if err != nil {
		return nil, fmt.Errorf("Failed to get TUN interface: %w", err)
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}
    addr, err := netlink.ParseAddr(virtIp + "/" + strconv.Itoa(virtPrefixLen))
    if err != nil {
        return nil, fmt.Errorf("Failed to assign IP to %v: %v", devs[0].Name(), err)
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
	return devs, nil
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
	mark := 9484
	lc := net.ListenConfig{
		Control: func(network, addr string, c syscall.RawConn) error {
			var soErr error
			err := c.Control(func(fd uintptr) {
				soErr = unix.SetsockoptInt(
					int(fd),
					unix.SOL_SOCKET, // level  : socket layer
					unix.SO_MARK,    // optname: SO_MARK
					mark,            // optval : 9484
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
			InitialStreamReceiveWindow:     10 * 1024 * 1024,  // 10 MB
    		MaxStreamReceiveWindow:         10 * 1024 * 1024,  // 10 MB
    		InitialConnectionReceiveWindow: 15 * 1024 * 1024,  // 15 MB
    		MaxConnectionReceiveWindow:     15 * 1024 * 1024,  // 15 MB
        },
	)
	if err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}
	defer ln.Close()

	p := connectip.Proxy{}
	mux := http.NewServeMux()
    ipToTunChan = make(map[netip.Addr](chan *packet))
    mu = &sync.RWMutex{}
	for i, dev := range tunTapDevice {
    	go func(d *water.Interface, id int) {
        	for {
				pkt := packetPool.Get().(*packet)
        		n, err := d.Read(pkt.buf)
        		if err != nil {
            		packetPool.Put(pkt) // return on error path too
                	logger.Error(fmt.Sprintf("queue#%d cannot read TUN/TAP device %v: %v", id, d.Name(), err))
            		cancel()
            		break
        		}
        		pkt.n = n
                // assuming we are only doing IPv4
                destIP, ok := netip.AddrFromSlice(pkt.buf[16:20])
                if ! ok {
            		packetPool.Put(pkt) // return on error path too
					if logger.ShouldLog(logger.TRACE) {
				    	logger.Trace(fmt.Sprintf("queue#%d cannot parse data to IP. Dropping packet.", id))
					}
                    continue
                }
				if logger.ShouldLog(logger.TRACE) {
					logger.Trace(fmt.Sprintf("queue#%d dest IP to filter %v",id, destIP.String()))
				}
				destIP = destIP.Unmap()
                mu.RLock()
                tunChan, ok := ipToTunChan[destIP]
                mu.RUnlock()
				if ok {
    				select {
    					case tunChan <- pkt:
    					default:
            				packetPool.Put(pkt) // return on error path too
							if logger.ShouldLog(logger.TRACE) {
        						logger.Trace(fmt.Sprintf("queue#%d client %s channel full, dropping packet.", id, destIP.String()))
    						}
					}
				} else {
            		packetPool.Put(pkt) // return on error path too
					if logger.ShouldLog(logger.TRACE) {
                    	logger.Trace(fmt.Sprintf("queue#%d cannot find connection for client IP = %s. Dropping packet.", id, destIP.String()))
                	}
				}
        	}
    	}(dev, i)
	}
	mux.HandleFunc("/vpn", func(w http.ResponseWriter, r *http.Request) {
        commonName := r.TLS.PeerCertificates[0].Subject.CommonName
    	clientId, err := strconv.ParseInt(commonName, 10, 64)
		if err != nil {
			logger.Info(fmt.Sprintf("Got invalid TLS common name %v: %v", commonName, err))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if logger.ShouldLog(logger.DEBUG) {
			logger.Debug(fmt.Sprintf("Handle new HTTP client %v", clientId))
		}
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

		if err := handleConn(&conCtx, make(chan *packet, 256), conn, ipProtocol, fdSnd); err != nil {
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

func handleConn(ctx *context.Context, tunChan chan *packet,  conn *connectip.Conn, ipProtocol uint8, fd int) error {
	setupCtx, setupCancel := context.WithTimeout(*ctx, 5*time.Second)
	defer setupCancel()
	if logger.ShouldLog(logger.DEBUG) {
    	logger.Debug("Start connectip flow")
	}
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
    ipToTunChan[addr] = tunChan
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
    	pktChan := make(chan []byte, 64)
    	// reader goroutine
    	go func() {
        	b := make([]byte, 1500)
        	for {
            	n, err := conn.ReadPacket(b)
            	if err != nil {
                	close(pktChan)
                	errChan <- err
                	return
            	}
            	pkt := make([]byte, n)
            	copy(pkt, b[:n])
            	pktChan <- pkt
        	}
    	}()
	
    	batch := utility.NewSocketBatch(fd)
    	ticker := time.NewTicker(5 * time.Millisecond)
    	defer ticker.Stop()
    	for {
        	select {
        	case pkt, ok := <-pktChan:
            	if !ok {
                	batch.Flush()
                	return
            	}
            	batch.Add(pkt)
				for len(pktChan) > 0 && !batch.Full() {
                	pkt = <-pktChan
                	batch.Add(pkt)
            	}
            	if batch.Full() {
                	if err := batch.Flush(); err != nil {
                    	logger.Error(fmt.Sprintf("sendmmsg error: %v", err))
                	}
            	}
        	case <-ticker.C:
            	if err := batch.Flush(); err != nil {
                	logger.Error(fmt.Sprintf("sendmmsg error: %v", err))
            	}
        	}
    	}
	}()

	timer := time.NewTimer(5 * time.Millisecond)
	defer timer.Stop()
	go func() {
		for {
            pkt, ok := <-tunChan
			if !ok {
				select {
        			case errChan <- fmt.Errorf("tunChan closed"):
        			default:
    			}
				return
			}
			if logger.ShouldLog(logger.TRACE) {
            	logger.Trace(fmt.Sprintf("WAN -> TUN: read %d bytes, payload = %x", pkt.n, pkt))
			}
			done := make(chan struct{})
			go func() {
            	defer close(done)
            	icmp, err := conn.WritePacket(pkt.buf[:pkt.n])
            	// handle icmp/err as before
				if err != nil {
					if errors.Is(err, net.ErrClosed) {
        				// fatal, connection is gone
						logger.Error(fmt.Sprintf("failed to write to a closed connection: %w", err))
						errChan <- err
        				return
    				}
					// maybe the packet queue is just full
					// as a VPN server we drop packet
					// and transportation layer (L4) can retry
					logger.Error(fmt.Sprintf("failed to write to connection, drop packet: %w", err))
				}
				if len(icmp) > 0 {
					if err := utility.SendOnSocket(fd, icmp); err != nil {
						logger.Error(fmt.Sprintf("failed to send ICMP packet: %v", err))
					}
				}
        	}()
			timer.Reset(5 * time.Millisecond)
        	select {
        		case <-done:
            		packetPool.Put(pkt)
        		case <-timer.C:
            		packetPool.Put(pkt) // timed out, drop packet
        	}
		}
	}()

	err := <-errChan
	logger.Error(fmt.Sprintf("error proxying: %v", err))
    mu.Lock()
    delete(ipToTunChan, addr)
    mu.Unlock()
	close(tunChan)
	for pkt := range tunChan {
		packetPool.Put(pkt)
	}
	conn.Close()
	<-errChan // wait for the other goroutine to finish
	unix.Close(fd)
	return err
}
