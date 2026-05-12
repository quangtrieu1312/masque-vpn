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
	"os/exec"
	"strconv"
	"strings"
	"time"
	"golang.org/x/sys/unix"
	"syscall"
	"os/signal"
	"runtime"
	
	connectip "github.com/quic-go/connect-ip-go"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"

	"github.com/quangtrieu1312/masque-vpn/client/config"
	"github.com/quangtrieu1312/masque-vpn/client/constants"
	"github.com/quangtrieu1312/masque-vpn/client/logger"
	"github.com/quangtrieu1312/masque-vpn/client/utility"
)

func PreUp(ctx *context.Context) {
    logger.LogInfo("Exec pre up")
    cmd := exec.Command("/sbin/ip", "rule", "add", "not", "fwmark", (*ctx).Value("FWMARK").(string), "table", "9000")
    logger.LogInfo(fmt.Sprintf("Running command: /sbin/ip"))
    _, err := cmd.Output()
    if err != nil {
        logger.LogFatal(fmt.Sprintf("Error running pre up command: %v", err))
    }
}

func PostUp() {
    logger.LogInfo("Exec post up")
}

func PostDown() {
    logger.LogInfo("Exec post down")
    cmd := exec.Command("/sbin/ip", "rule", "del", "table", "9000")
    logger.LogInfo(fmt.Sprintf("Running command: /sbin/ip"))
    _, err := cmd.Output()
    if err != nil {
        logger.LogFatal(fmt.Sprintf("Error running post down command: %v", err))
    }
    cmd = exec.Command("/sbin/ip", "route", "flush", "table", "9000")
    logger.LogInfo(fmt.Sprintf("Running command: /sbin/ip"))
	_, err = cmd.Output()
    if err != nil {
        logger.LogFatal(fmt.Sprintf("Error running post down command: %v", err))
    }
}

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
	sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan,
        syscall.SIGHUP,
        syscall.SIGINT,
        syscall.SIGTERM,
        syscall.SIGQUIT)
	go func() {
    	<-sigChan
    	PostDown()
    	cancel()
	}()
    config.Load(&ctx)
    logLevel := ctx.Value("LOG_LEVEL").(string)
    logPath := constants.LOG_PATH
    logger.UpdateLogLevelName(logLevel)
    logger.UpdateLogPath(logPath)
    f, err := os.OpenFile(logger.GetLogPath(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
    if err != nil {
        log.Fatalf("Error opening file: %v", err)
    } else {
        wrt := io.MultiWriter(os.Stdout, f)
        log.SetOutput(wrt)
    }
    defer f.Close()
    serverInfo := ctx.Value("SERVER").(string)
    serverHost := serverInfo
    serverPort := 443
    if portIndex := strings.Index(serverInfo, ":"); portIndex > -1 {
        host := serverInfo[:portIndex]
        port, err := strconv.Atoi(serverInfo[portIndex+1:])
        if err != nil {
		    logger.LogFatal(fmt.Sprintf("Failed to parse server port: %v", err))
            os.Exit(1)
        }
        serverHost = host
        serverPort = port
    }
    var serverIp netip.Addr
    if ip, err := netip.ParseAddr(serverHost); err != nil {
        logger.LogDebug(fmt.Sprintf("Resolving %v", serverHost))
        if ips, err := net.LookupIP(serverHost); err != nil {
            logger.LogFatal(fmt.Sprintf("Failed to resolve server FQDN: %v", err))
            os.Exit(1)
        } else {
            serverIp = netip.MustParseAddr(ips[0].String())
        }
    } else {
        serverIp = ip
    }
    ctx = context.WithValue(ctx, "SERVER_IP", serverIp.String())
    logger.LogInfo(fmt.Sprintf("Connecting to %v", serverIp))
	serverAddr := netip.AddrPortFrom(serverIp, uint16(serverPort))
    enableKeyLog, err := strconv.ParseBool(ctx.Value("ENABLE_KEY_LOG").(string))
    if err != nil {
		logger.LogError(fmt.Sprintf("Cannot parse ENABLE_KEY_LOG config, default to `false`"))
        enableKeyLog = false
    }
    keyLogPath := ctx.Value("KEY_LOG_PATH").(string)
    errChan := make(chan error)
    isRunningChan := make(chan bool)
    go func(contxt context.Context) {
        for {
            select {
            case cerr := <-errChan:
                logger.LogError(fmt.Sprintf("Encounter error: %v", cerr))
                cancel()
                return
            case isRunning := <- isRunningChan:
                if (isRunning) {
                    logger.LogInfo("Masque is up")
                    PostUp()
                } else {
                    logger.LogInfo("Masque is down")
                    PostDown()
                    cancel()
                	return
                }
            }
        }
    }(ctx)
    go func(contxt context.Context) {
        errorThreshold := 5
		connID := fmt.Sprintf("conn#%d", 6-errorThreshold)
        logger.LogDebug(fmt.Sprintf("Retry threshold = %d", errorThreshold))
        for {
            logger.LogTrace(fmt.Sprintf("Number of retry attempts left = %d", errorThreshold))
            if errorThreshold < 0 {
                errChan <- fmt.Errorf("Out of attempts")
            }
	        routes, localPrefixes, ipconn, err := establishMASQUEConn(ctx, serverAddr, serverHost, enableKeyLog, keyLogPath)
	        if err != nil {
                logger.LogError(fmt.Sprintf("Failed to establish MASQUE connection: %v", err))
                errorThreshold--
                continue
	        }
            devs, derr := establishTunTapAndRoutes(ctx, routes, localPrefixes)
            if derr != nil {
                logger.LogError(fmt.Sprintf("Failed to establish TUN/TAP device or VPN routes: %v", derr))
                errorThreshold--
                continue
            }
	        logger.LogDebug(fmt.Sprintf("Created TUN device: %s in the background", devs[0].Name()))
            eChan := make(chan error, runtime.NumCPU() + 1)
			connCtx, connCancel := context.WithCancel(ctx)
            go func() {
                cerr := <-eChan
                errorThreshold--
                logger.LogError(fmt.Sprintf("Tunneling error: %v", cerr))
				connCancel()
                ipconn.Close()
				for _, dev := range devs {
					dev.Close()
				}
            }()
            tunnel(connCtx, connID, ipconn, devs, isRunningChan, eChan)
        }
    }(ctx)
    <-ctx.Done()
}

func healthCheck(ctx context.Context) error {
	//TODO
    ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    return nil
}

func establishMASQUEConn(ctx context.Context, serverAddr netip.AddrPort, serverFQDN string, enableKeyLog bool, keyLogPath string) ([]connectip.IPRoute, []netip.Prefix, *connectip.Conn, error) {
    fwmark, err := strconv.ParseInt(ctx.Value("FWMARK").(string), 10, 32)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to parse FWMARK config to number: %w", err)
	}
	lc := net.ListenConfig{
    	Control: func(network, addr string, c syscall.RawConn) error {
        	var soErr error
        	err := c.Control(func(fd uintptr) {
            	soErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(fwmark))
        	})
        	if err != nil {
            	return err
        	}
        	return soErr
    	},
	}
	pc, err := lc.ListenPacket(context.Background(), "udp", "0.0.0.0:0")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to listen on UDP: %w", err)
	}
	udpConn, ok := pc.(*net.UDPConn)
	if !ok {
		return nil, nil, nil, fmt.Errorf("expected *net.UDPConn, got %T", pc)
	}

    // load tls configuration
    CertFilePath := constants.CLIENT_CERT_PATH
    KeyFilePath := constants.CLIENT_KEY_PATH
    CACertFilePath := constants.SERVER_CA_PATH
	cert, err := tls.LoadX509KeyPair(CertFilePath, KeyFilePath)
	if err != nil {
        panic(fmt.Sprintf("Cannot load client key pair: %v",err))
	}
	// Configure the client to trust TLS server certs issued by a CA.
	certPool, err := x509.SystemCertPool()
	if err != nil {
        panic(fmt.Sprintf("Cannot create cert pool: %v", err))
	}
	if caCertPEM, err := os.ReadFile(CACertFilePath); err != nil {
        panic(fmt.Sprintf("Cannot read CA cert file: %v", err))
	} else if ok := certPool.AppendCertsFromPEM(caCertPEM); !ok {
		panic("Invalid cert in CA PEM")
	}
    tlsConf :=  &tls.Config {
		ServerName:         serverFQDN,
		NextProtos:         []string{http3.NextProtoH3},
        RootCAs:            certPool,
		Certificates:       []tls.Certificate{cert},
    }
    if enableKeyLog {
        keyLogPath := ctx.Value("KEY_LOG_PATH").(string)
        if keyLogPath == "" {
		    logger.LogError(fmt.Sprintf("Cannot parse KEY_LOG_PATH config, default to `keys.txt`"))
            keyLogPath = "keys.txt"
        }
        keyLog, err := os.Create(keyLogPath)
	    defer keyLog.Close()
	    if err != nil {
		    logger.LogError(fmt.Sprintf("failed to create key log file: %v", err))
	    }
        tlsConf.KeyLogWriter = keyLog
    }
	dialCtx, dialCancel := context.WithTimeout(ctx, 15*time.Second)
	defer dialCancel()
	conn, err := quic.Dial(
		dialCtx,
		udpConn,
		&net.UDPAddr{IP: serverAddr.Addr().AsSlice(), Port: int(serverAddr.Port())},
		tlsConf,
		&quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
            KeepAlivePeriod: 5*time.Second,
			InitialStreamReceiveWindow:     10 * 1024 * 1024,  // 10 MB
    		MaxStreamReceiveWindow:         10 * 1024 * 1024,  // 10 MB
    		InitialConnectionReceiveWindow: 15 * 1024 * 1024,  // 15 MB
    		MaxConnectionReceiveWindow:     15 * 1024 * 1024,  // 15 MB
		},
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	hconn := tr.NewClientConn(conn)

	template := uritemplate.MustNew(fmt.Sprintf("https://masque:%d/vpn", serverAddr.Port()))
	ipconn, rsp, err := connectip.Dial(dialCtx, hconn, template)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}
	logger.LogDebug(fmt.Sprintf("connected to VPN server: %s", serverAddr))

	routes, err := ipconn.Routes(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get routes: %w", err)
	}
	localPrefixes, err := ipconn.LocalPrefixes(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to get local prefixes: %w", err)
	}

	return routes, localPrefixes, ipconn, nil
}

func establishTunTapAndRoutes(ctx context.Context, routes []connectip.IPRoute, localPrefixes []netip.Prefix) ([]*water.Interface, error) {
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

    // link setup only needs to happen once, on devs[0]
    link, err := netlink.LinkByName(devName)
    if err != nil {
        return nil, fmt.Errorf("failed to get TUN interface: %w", err)
    }
    for _, p := range localPrefixes {
        if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: utility.PrefixToIPNet(p)}); err != nil {
            return nil, fmt.Errorf("failed to add address assigned by peer: %w", err)
        }
    }
    if err := netlink.LinkSetUp(link); err != nil {
        return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
    }

	for _, route := range routes {
		logger.LogDebug(fmt.Sprintf("adding routes for %s - %s (protocol: %d)", route.StartIP, route.EndIP, route.IPProtocol))
		for _, prefix := range route.Prefixes() {
            cmd := exec.Command("/sbin/ip", "route", "add", prefix.String() , "dev", devName, "table", "9000")
            logger.LogInfo(fmt.Sprintf("Adding route: %v", prefix.String()))
            _, err := cmd.Output()
            if err != nil {
                return nil, fmt.Errorf("Failed to add route: %v", err)
            }
		}
	}
    PreUp(&ctx)
    return devs, nil
}

func tunnel(ctx context.Context, connID string, ipconn *connectip.Conn, devs []*water.Interface, isRunningChan chan bool, errChan chan error) {
	// ONE goroutine reads from MASQUE, round-robins to TUN queues
	go func() {
    	i := 0
        b := make([]byte, 1500)
    	for {
        	n, err := ipconn.ReadPacket(b)
        	if err != nil {
            	select {
                	case errChan <- fmt.Errorf("fatal read from MASQUE: %w", err):
                	default:
            	}
            	return
        	}
        	if _, err := devs[i%len(devs)].Write(b[:n]); err != nil {
            	select {
                	case errChan <- fmt.Errorf("failed to write to TUN queue %d: %w", i%len(devs), err):
                	default:
            	}
        	}
        	i++
    	}
	}()
	
	// N goroutines each read from their own TUN queue fd → write to MASQUE
	for i, dev := range devs {
    	go func(d *water.Interface, id int) {
            b := make([]byte, 1500)
        	for {
            	n, err := d.Read(b)
            	if err != nil {
                	select {
                    	case errChan <- fmt.Errorf("%s queue#%d fatal read from TUN: %w", connID, id, err):
                    	default:
                	}
                	return
            	}
            	icmp, err := ipconn.WritePacket(b[:n])
            	if err != nil {
                	select {
                    	case errChan <- fmt.Errorf("%s queue#%d failed to write to MASQUE: %w", connID, id, err):
                    	default:
                	}
            	}
            	if len(icmp) > 0 {
                	if _, err := d.Write(icmp); err != nil {
                    	select {
                        	case errChan <- fmt.Errorf("%s queue#%d failed to write ICMP: %w", connID, id, err):
                        	default:
                    	}
                	}
            	}
        	}
    	}(dev, i)
	}
    isRunningChan <- true
    <-ctx.Done()
}
