//go:build linux

package xdp

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type Loader struct {
	objs masqueXDPObjects
	link link.Link
}

// Load attaches the XDP program to ifaceName.
// Tries native (driver) mode first, falls back to generic (SKB) mode.
func Load(ifaceName string) (*Loader, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}

	objs := masqueXDPObjects{}
	if err := loadMasqueXDPObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading XDP objects: %w", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.MasqueXdpProg,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		// NIC or driver doesn't support native XDP — fall back
		l, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.MasqueXdpProg,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			objs.Close()
			return nil, fmt.Errorf("attaching XDP (native and generic both failed): %w", err)
		}
	}

	return &Loader{objs: objs, link: l}, nil
}

// XskMap returns the XSKMAP so AF_XDP sockets can register themselves.
func (l *Loader) XskMap() *ebpf.Map {
	return l.objs.XsksMap
}

// Close detaches the XDP program and frees BPF resources.
func (l *Loader) Close() {
	l.link.Close()
	l.objs.Close()
}
