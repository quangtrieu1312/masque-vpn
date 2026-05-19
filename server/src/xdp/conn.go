//go:build linux

package xdp

import (
	"encoding/binary"
	"fmt"
	"net"
	"sync/atomic"
	"time"
	"runtime"

	"github.com/asavie/xdp"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// Conn implements net.PacketConn over AF_XDP sockets.
// One XSK socket is created per NIC queue.
type Conn struct {
	sockets   []*xdp.Socket
	fdToSock  map[int]*xdp.Socket
	epollFd   int
	localAddr *net.UDPAddr
	srcMAC    net.HardwareAddr
	gwMAC     net.HardwareAddr              // fallback until first packet arrives
	peerMAC   atomic.Pointer[net.HardwareAddr] // learned from first inbound frame src MAC
	txIdx     atomic.Uint64
	done      chan struct{}
	epollEvents	[]unix.EpollEvent
}

// NewConn creates AF_XDP sockets for each NIC queue, registers them into xskMap,
// and returns a net.PacketConn ready for quic-go.
func NewConn(
	iface *net.Interface,
	xskMap *ebpf.Map,
	localAddr *net.UDPAddr,
	numQueues int,
	mode XDPMode,
) (*Conn, error) {
	// If localAddr has an unspecified IP (0.0.0.0), resolve the real
    // IP from the interface. The raw Ethernet frames we build need a
    // valid unicast source — the kernel won't fill this in for us.
    frameLocalAddr := localAddr
    if localAddr.IP == nil || localAddr.IP.IsUnspecified() {
        ifaceIP, err := resolveIfaceIP(iface)
        if err != nil {
            return nil, fmt.Errorf("resolving IP for %s: %w", iface.Name, err)
        }
        frameLocalAddr = &net.UDPAddr{IP: ifaceIP, Port: localAddr.Port}
    }

	gwMAC, err := resolveNextHopMAC(iface, localAddr.IP)
	if err != nil {
		return nil, fmt.Errorf("resolving next-hop MAC: %w", err)
	}

	epfd, err := unix.EpollCreate1(0)
	if err != nil {
		return nil, fmt.Errorf("epoll_create1: %w", err)
	}
	sockets := make([]*xdp.Socket, numQueues)
	fdToSock := make(map[int]*xdp.Socket, numQueues)
	for i := 0; i < numQueues; i++ {
		sock, err := xdp.NewSocket(iface.Index, i, nil)
		if err != nil {
			closeSockets(sockets[:i])
			unix.Close(epfd)
			return nil, fmt.Errorf("XSK queue %d (XDP mode %s): %w", i, mode, err)
		}

		// Pre-populate the fill ring so the kernel has UMEM frames
		// to deliver incoming packets into. Without this, xsk_generic_rcv
		// returns -ENOMEM on every packet and nothing ever arrives.
		nFill := sock.NumFreeFillSlots()
		if nFill > 0 {
    		sock.Fill(sock.GetDescs(nFill))
		}

		if err := xskMap.Update(uint32(i), uint32(sock.FD()), ebpf.UpdateAny); err != nil {
			sock.Close()
			closeSockets(sockets[:i])
			unix.Close(epfd)
			return nil, fmt.Errorf("XSKMAP update queue %d: %w", i, err)
		}

		// store FD in epoll data so we can look up the socket on wake
		var ev unix.EpollEvent
		ev.Events = unix.EPOLLIN
		ev.Fd = int32(sock.FD())
		if err := unix.EpollCtl(epfd, unix.EPOLL_CTL_ADD, sock.FD(), &ev); err != nil {
			sock.Close()
			closeSockets(sockets[:i])
			unix.Close(epfd)
			return nil, fmt.Errorf("epoll_ctl queue %d: %w", i, err)
		}

		sockets[i] = sock
		fdToSock[sock.FD()] = sock
	}

	return &Conn{
		sockets:   sockets,
		fdToSock:  fdToSock,
		epollFd:   epfd,
		localAddr: frameLocalAddr,
		srcMAC:    iface.HardwareAddr,
		gwMAC:     gwMAC,
		done:      make(chan struct{}),
		epollEvents: make([]unix.EpollEvent, numQueues),
	}, nil
}

// ReadFrom blocks until a UDP packet arrives on any queue.
// Strips Ethernet + IPv4 + UDP headers and returns the payload.
func (c *Conn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		select {
		case <-c.done:
			return 0, nil, net.ErrClosed
		default:
		}

		n, err := unix.EpollWait(c.epollFd, c.epollEvents, 5 /* ms timeout */)
		if err != nil {
			if err == unix.EINTR {
				continue
			}
			return 0, nil, fmt.Errorf("epoll_wait: %w", err)
		}
		gotPacket := false
		for i := 0; i < n; i++ {
			fd := int(c.epollEvents[i].Fd)
			sock, ok := c.fdToSock[fd]
			if !ok {
				fmt.Printf("DEBUG: epoll fd=%d not in fdToSock keys=%v\n", fd, c.fdToSock)
				continue
			}

			// Reap any completed TX descriptors so the UMEM pool
			// doesn't exhaust. Safe to call here since we hold no
			// TX lock — AF_XDP completion ring is separate from RX.
			if nc := sock.NumCompleted(); nc > 0 {
				sock.Complete(nc)
			}

			descs := sock.Receive(1)
			if len(descs) == 0 {
				continue
			}
			gotPacket = true
			frame := sock.GetFrame(descs[0])

			// Learn the peer's L2 next-hop from the Ethernet src field
			// (bytes 6-11) and store it for WriteTo. One client per Conn,
			// so a single atomic pointer is all we need — no map.
			if len(frame) >= 12 {
				mac := make(net.HardwareAddr, 6)
				copy(mac, frame[6:12])
				c.peerMAC.Store(&mac)
			}

			pktLen, addr, err := parseUDPFrame(frame, p)
			sock.Fill(descs) // return descriptor to fill ring
			if err != nil {
				continue // skip malformed frames
			}
			return pktLen, addr, nil
		}
		if !gotPacket {
			runtime.Gosched()
		}
	}
}

// WriteTo builds a raw Ethernet+IPv4+UDP frame and sends it via AF_XDP.
func (c *Conn) WriteTo(p []byte, addr net.Addr) (int, error) {
	select {
	case <-c.done:
		return 0, net.ErrClosed
	default:
	}

	dst, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("expected *net.UDPAddr, got %T", addr)
	}

	// round-robin across TX queues
	idx := int(c.txIdx.Add(1) % uint64(len(c.sockets)))
	sock := c.sockets[idx]

	// Reap completed TX descriptors before allocating new ones,
	// so the UMEM free pool never exhausts.
	if nc := sock.NumCompleted(); nc > 0 {
		sock.Complete(nc)
	}

	descs := sock.GetDescs(1)
	if len(descs) == 0 {
		return 0, fmt.Errorf("TX ring full, dropping packet")
	}
	frame := sock.GetFrame(descs[0])

	// Use the peer's MAC learned from the first inbound frame.
	// Falls back to gwMAC only before the first packet has arrived.
	dstMAC := c.gwMAC
	if p := c.peerMAC.Load(); p != nil {
		dstMAC = *p
	}

	total := buildUDPFrame(frame, c.srcMAC, dstMAC, c.localAddr, dst, p)
	descs[0].Len = uint32(total)
	sock.Transmit(descs)
	sock.Poll(0) // kick the TX
	return len(p), nil
}

func (c *Conn) Close() error {
	close(c.done)
	unix.Close(c.epollFd)
	closeSockets(c.sockets)
	return nil
}

func (c *Conn) LocalAddr() net.Addr                { return c.localAddr }
func (c *Conn) SetDeadline(t time.Time) error      { return nil }
func (c *Conn) SetReadDeadline(t time.Time) error  { return nil }
func (c *Conn) SetWriteDeadline(t time.Time) error { return nil }

// --- frame helpers ---

// parseUDPFrame strips eth(14) + ipv4(ihl*4) + udp(8) headers.
func parseUDPFrame(frame, dst []byte) (int, net.Addr, error) {
	const ethHdr = 14
	if len(frame) < ethHdr+20+8 {
		return 0, nil, fmt.Errorf("frame too short: %d bytes", len(frame))
	}
	ihl := int(frame[ethHdr]&0x0f) * 4
	udpBase := ethHdr + ihl
	if len(frame) < udpBase+8 {
		return 0, nil, fmt.Errorf("frame too short for UDP header")
	}
	srcIP := make(net.IP, 4)
	copy(srcIP, frame[ethHdr+12:ethHdr+16])
	srcPort := binary.BigEndian.Uint16(frame[udpBase : udpBase+2])
	n := copy(dst, frame[udpBase+8:])
	return n, &net.UDPAddr{IP: srcIP, Port: int(srcPort)}, nil
}

// buildUDPFrame writes eth + ipv4 + udp + payload into frame.
// Caller must ensure frame is large enough (42 + len(payload)).
func buildUDPFrame(frame []byte, srcMAC, dstMAC net.HardwareAddr, src, dst *net.UDPAddr, payload []byte) int {
	// Ethernet
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], srcMAC)
	frame[12], frame[13] = 0x08, 0x00 // EtherType IPv4

	// IPv4
	ipLen := 20 + 8 + len(payload)
	frame[14] = 0x45 // version=4, IHL=5 (no options)
	frame[15] = 0x00 // DSCP/ECN
	binary.BigEndian.PutUint16(frame[16:18], uint16(ipLen))
	binary.BigEndian.PutUint16(frame[18:20], 0)    // ID
	binary.BigEndian.PutUint16(frame[20:22], 0x40) // DF flag, no fragment offset
	frame[22] = 64                                  // TTL
	frame[23] = 17                                  // proto = UDP
	frame[24], frame[25] = 0, 0                    // checksum placeholder
	copy(frame[26:30], src.IP.To4())
	copy(frame[30:34], dst.IP.To4())
	binary.BigEndian.PutUint16(frame[24:26], ipv4Checksum(frame[14:34]))

	// UDP (checksum=0 is legal for IPv4)
	binary.BigEndian.PutUint16(frame[34:36], uint16(src.Port))
	binary.BigEndian.PutUint16(frame[36:38], uint16(dst.Port))
	binary.BigEndian.PutUint16(frame[38:40], uint16(8+len(payload)))
	frame[40], frame[41] = 0, 0

	copy(frame[42:], payload)
	return 42 + len(payload)
}

func ipv4Checksum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i:]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// SetReadBuffer sets SO_RCVBUF on every underlying XSK file descriptor.
// quic-go calls this via interface{ SetReadBuffer(int) error } —
// without it, quic-go logs a "Not a *net.UDPConn?" warning and skips
// buffer tuning entirely. AF_XDP's actual data path uses UMEM, not the
// kernel socket buffer, but setting this silences the warning and
// applies the option consistently across all queue sockets.
func (c *Conn) SetReadBuffer(bytes int) error {
	for _, sock := range c.sockets {
		if err := unix.SetsockoptInt(sock.FD(), unix.SOL_SOCKET, unix.SO_RCVBUF, bytes); err != nil {
			return fmt.Errorf("SO_RCVBUF on XSK fd %d: %w", sock.FD(), err)
		}
	}
	return nil
}

// SetWriteBuffer sets SO_SNDBUF on every underlying XSK file descriptor.
func (c *Conn) SetWriteBuffer(bytes int) error {
	for _, sock := range c.sockets {
		if err := unix.SetsockoptInt(sock.FD(), unix.SOL_SOCKET, unix.SO_SNDBUF, bytes); err != nil {
			return fmt.Errorf("SO_SNDBUF on XSK fd %d: %w", sock.FD(), err)
		}
	}
	return nil
}

func closeSockets(sockets []*xdp.Socket) {
	for _, s := range sockets {
		if s != nil {
			s.Close()
		}
	}
}

// resolveIfaceIP returns the first non-loopback unicast IPv4 address on iface.
func resolveIfaceIP(iface *net.Interface) (net.IP, error) {
    addrs, err := iface.Addrs()
    if err != nil {
        return nil, err
    }
    for _, a := range addrs {
        var ip net.IP
        switch v := a.(type) {
        case *net.IPNet:
            ip = v.IP
        case *net.IPAddr:
            ip = v.IP
        }
        if ip4 := ip.To4(); ip4 != nil && !ip4.IsLoopback() {
            return ip4, nil
        }
    }
    return nil, fmt.Errorf("no IPv4 address found on %s", iface.Name)
}
