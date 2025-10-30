package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"time"
    "strings"
    //"sync"

	connectip "github.com/quic-go/connect-ip-go"
	//"golang.org/x/sys/unix"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
)

func parseConfig(ctx *context.Context) {
    var configPath string
    flag.StringVar(&configPath,"f", "/etc/masque/masque0.conf", "Path to config file")
    file, err := os.Open(configPath)
    if err != nil {
        log.Fatalf("Failed to open config file %v: %v", configPath, err)
        os.Exit(1)
    }
    defer file.Close()
    scanner := bufio.NewScanner(file)
    for scanner.Scan() {
        data := strings.Trim(scanner.Text(), " \t")
        if len(data) == 0 {
            continue
        }
        isKey := true
        k := ""
        v := ""
        for pos, char := range data {
            if (pos == 0 && char == '#') {
                continue
            }
            if (isKey && char == '=') {
                isKey = false
                continue
            }
            if (isKey) {
                k+=string(char)
            } else {
                v+=string(char)
            }
        }
        if (k == "") {
            log.Fatalf("Invalid config format")
        }
        (*ctx) = context.WithValue(*ctx, k, v)
    }
}

func main() {
    ctx, cancel := context.WithCancel(context.Background())
    defer cancel()
    parseConfig(&ctx)
    logLevel := ctx.Value("LOG_LEVEL").(string)
    logPath := ctx.Value("LOG_PATH").(string)
    UpdateLoggerInstance(ConvertStringToLogLevel(logLevel), logPath)
    f, err := os.OpenFile(GetLogPath(), os.O_RDWR|os.O_CREATE|os.O_APPEND, 0644)
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
		    LogFatal(fmt.Sprintf("Failed to parse server port: %v", err))
            os.Exit(1)
        }
        serverHost = host
        serverPort = port
    }
    var serverIp netip.Addr
    if ip, err := netip.ParseAddr(serverHost); err != nil {
        LogDebug(fmt.Sprintf("Resolving %v", serverHost))
        if ips, err := net.LookupIP(serverHost); err != nil {
            LogFatal(fmt.Sprintf("Failed to resolve server FQDN: %v", err))
            os.Exit(1)
        } else {
            serverIp = netip.MustParseAddr(ips[0].String())
        }
    } else {
        serverIp = ip
    }
    LogInfo(fmt.Sprintf("Connecting to %v", serverIp))
	serverAddr := netip.AddrPortFrom(serverIp, uint16(serverPort))
    enableKeyLog, err := strconv.ParseBool(ctx.Value("ENABLE_KEY_LOG").(string))
    if err != nil {
		LogError(fmt.Sprintf("Cannot parse ENABLE_KEY_LOG config, default to `false`"))
        enableKeyLog = false
    }
    keyLogPath := ctx.Value("KEY_LOG_PATH").(string)
    errChan := make(chan error)
    tunneling := make(chan bool)
    go func(contxt context.Context) {
        for {
            select {
            case cerr := <-errChan:
                LogError(fmt.Sprintf("Encounter error: %v", cerr))
                cancel()
                return
            case isRunning := <- tunneling:
                if (isRunning) {
                    LogInfo("Masque is up")
                } else {
                    LogInfo("Masque is down")
                    cancel()
                }
                return
            }
        }
    }(ctx)
    go func(contxt context.Context) {
        errorThreshold := 5
        LogDebug(fmt.Sprintf("Retry threshold = %d", errorThreshold))
        for {
            LogTrace(fmt.Sprintf("Number of retry attempts left = %d", errorThreshold))
            if errorThreshold < 0 {
                errChan <- fmt.Errorf("Out of attempts")
            }
	        routes, localPrefixes, ipconn, err := establishMASQUEConn(ctx, serverAddr, serverHost, enableKeyLog, keyLogPath)
	        if err != nil {
                LogError(fmt.Sprintf("Failed to establish MASQUE connection: %v", err))
                errorThreshold--
                continue
	        }
            dev, derr := establishTunTapAndRoutes(ctx, routes, localPrefixes)
            if derr != nil {
                LogError(fmt.Sprintf("Failed to establish TUN/TAP device or VPN routes: %v", derr))
                errorThreshold--
                continue
            }
	        LogDebug(fmt.Sprintf("Created TUN device: %s in the background", dev.Name()))
            eChan := make(chan error) 
            go func() {
                cerr := <-eChan
                errorThreshold--
                LogError(fmt.Sprintf("Tunneling error: %v", cerr))
                ipconn.Close()
                dev.Close()
            }()
            tunnel(ctx, ipconn, dev, tunneling, eChan)
        }
    }(ctx)
    <-ctx.Done()
}

func healthCheck(ctx context.Context) error {
    ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    return nil
}

func establishMASQUEConn(ctx context.Context, serverAddr netip.AddrPort, serverFQDN string, enableKeyLog bool, keyLogPath string) ([]connectip.IPRoute, []netip.Prefix, *connectip.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx,2*time.Second)
	defer cancel()
    udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to listen on UDP: %w", err)
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
    CertFilePath := ctx.Value("CLIENT_CERT_PATH").(string)
    KeyFilePath := ctx.Value("CLIENT_KEY_PATH").(string)
    CACertFilePath := ctx.Value("SERVER_CA_PATH").(string)
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
		    LogError(fmt.Sprintf("Cannot parse KEY_LOG_PATH config, default to `keys.txt`"))
            keyLogPath = "keys.txt"
        }
        keyLog, err := os.Create(keyLogPath)
	    defer keyLog.Close()
	    if err != nil {
		    LogError(fmt.Sprintf("failed to create key log file: %v", err))
	    }
        tlsConf.KeyLogWriter = keyLog
    }
	conn, err := quic.Dial(
		ctx,
		udpConn,
		&net.UDPAddr{IP: serverAddr.Addr().AsSlice(), Port: int(serverAddr.Port())},
		tlsConf,
		&quic.Config{
			EnableDatagrams:   true,
			InitialPacketSize: 1350,
            KeepAlivePeriod: 5*time.Second,
		},
	)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial QUIC connection: %w", err)
	}

	tr := &http3.Transport{EnableDatagrams: true}
	hconn := tr.NewClientConn(conn)

	template := uritemplate.MustNew(fmt.Sprintf("https://masque:%d/vpn", serverAddr.Port()))
	ipconn, rsp, err := connectip.Dial(ctx, hconn, template)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to dial connect-ip connection: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, nil, nil, fmt.Errorf("unexpected status code: %d", rsp.StatusCode)
	}
	LogDebug(fmt.Sprintf("connected to VPN server: %s", serverAddr))

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

func establishTunTapAndRoutes(ctx context.Context, routes []connectip.IPRoute, localPrefixes []netip.Prefix) (*water.Interface, error) {
	dev, err := water.New(water.Config{DeviceType: water.TUN})
	if err != nil {
		return nil, fmt.Errorf("failed to create TUN device: %w", err)
	}
	LogDebug(fmt.Sprintf("created TUN device: %s", dev.Name()))

	link, err := netlink.LinkByName(dev.Name())
	if err != nil {
		return nil, fmt.Errorf("failed to get TUN interface: %w", err)
	}
	for _, p := range localPrefixes {
		if err := netlink.AddrAdd(link, &netlink.Addr{IPNet: PrefixToIPNet(p)}); err != nil {
			return nil, fmt.Errorf("failed to add address assigned by peer %s: %w", p, err)
		}
	}
	if err := netlink.LinkSetUp(link); err != nil {
		return nil, fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	for _, route := range routes {
		LogDebug(fmt.Sprintf("adding routes for %s - %s (protocol: %d)", route.StartIP, route.EndIP, route.IPProtocol))
		for _, prefix := range route.Prefixes() {
			r := &netlink.Route{
				LinkIndex: link.Attrs().Index,
				Dst:       PrefixToIPNet(prefix),
			}
			if err := netlink.RouteAdd(r); err != nil {
				return nil, fmt.Errorf("failed to add route: %w", err)
			}
		}
	}
    return dev, nil
}

func tunnel(ctx context.Context, ipconn *connectip.Conn, dev *water.Interface, isRunningChan chan bool, errChan chan error) {
    go func() {
		for {
			b := make([]byte, 1500)
			n, rerr := ipconn.ReadPacket(b)
            if rerr != nil {
				errChan <- fmt.Errorf("Failed to read from QUIC tunnel: %w", rerr)
                isRunningChan <- false
            }
            LogTrace(fmt.Sprintf("Read %d bytes from tunnel: %x", n, b[:n]))
            _, werr := dev.Write(b[:n])
            if werr != nil {
				errChan <- fmt.Errorf("Failed to write to TUN/TAP device: %w", werr)
                isRunningChan <- false
            }
		}
	}()

	go func() {
		for {
			b := make([]byte, 1500)
            n, rerr := dev.Read(b)
            if rerr != nil {
                errChan <- fmt.Errorf("Failed to read from TUN/TAP device: %w", rerr)
                isRunningChan <- false
			}
            LogTrace(fmt.Sprintf("Read %d bytes from TUN/TAP device: %x", n, b[:n]))
			icmp, werr := ipconn.WritePacket(b[:n])
            if werr != nil {
				errChan <- fmt.Errorf("Failed to write to QUIC tunnel: %w", werr)
                isRunningChan <- false
            }
			if len(icmp) > 0 {
				LogTrace(fmt.Sprintf("Sending ICMP packet on %s", dev.Name()))
				if _, err := dev.Write(icmp); err != nil {
                    errChan <- fmt.Errorf("Failed to write ICMP packet: %v", err)
                    isRunningChan <- false
				}
			}
		}
	}()
    isRunningChan <- true
    <-ctx.Done()
}
