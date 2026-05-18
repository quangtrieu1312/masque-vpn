//go:build linux

package xdp

import (
	"fmt"
	"net"
	"time"

	"github.com/vishvananda/netlink"
)

// resolveNextHopMAC finds the MAC address of the next hop for outbound packets.
// If the ARP entry is stale or missing it probes the gateway and retries.
func resolveNextHopMAC(iface *net.Interface, localIP net.IP) (net.HardwareAddr, error) {
	gwIP, err := defaultGatewayIP()
	if err != nil {
		return nil, fmt.Errorf("finding default gateway: %w", err)
	}

	// Fast path: already in the neighbour cache.
	if mac, err := lookupNeighbourMAC(iface.Index, gwIP); err == nil {
		return mac, nil
	}

	// Slow path: trigger kernel ARP resolution by connecting a UDP socket.
	// connect() forces a route + neighbour lookup without sending any data.
	if err := probeARP(gwIP); err != nil {
		return nil, fmt.Errorf("ARP probe for gateway %s: %w", gwIP, err)
	}

	// Retry for up to 1 second.
	for range 5 {
		time.Sleep(200 * time.Millisecond)
		if mac, err := lookupNeighbourMAC(iface.Index, gwIP); err == nil {
			return mac, nil
		}
	}
	return nil, fmt.Errorf("ARP resolution timed out for gateway %s", gwIP)
}

// probeARP triggers kernel ARP resolution for ip without sending any data.
// connect() on a UDP socket forces the kernel to resolve the neighbour entry.
func probeARP(ip net.IP) error {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: ip, Port: 1})
	if err != nil {
		return err
	}
	conn.Close()
	return nil
}

// defaultGatewayIP returns the IPv4 address of the default route gateway.
func defaultGatewayIP() (net.IP, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("listing routes: %w", err)
	}
	for _, r := range routes {
		if r.Dst == nil && r.Gw != nil { // default route
			return r.Gw, nil
		}
	}
	return nil, fmt.Errorf("no default IPv4 route found")
}

// lookupNeighbourMAC looks up the MAC for ip in the kernel neighbour (ARP) table.
func lookupNeighbourMAC(ifaceIndex int, ip net.IP) (net.HardwareAddr, error) {
	neighs, err := netlink.NeighList(ifaceIndex, netlink.FAMILY_V4)
	if err != nil {
		return nil, fmt.Errorf("listing neighbours: %w", err)
	}
	for _, n := range neighs {
		if n.IP.Equal(ip) && len(n.HardwareAddr) > 0 {
			return n.HardwareAddr, nil
		}
	}
	return nil, fmt.Errorf("no ARP entry for %s on interface %d", ip, ifaceIndex)
}
