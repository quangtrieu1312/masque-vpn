//go:build linux

package xdp

import (
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type XDPMode int

const (
	// XDPModeNative means the XDP program runs inside the NIC driver,
	// before the kernel network stack. Requires driver support (e.g. virtio_net,
	// i40e, mlx5). Zero-copy is *possible* in this mode (driver-dependent),
	// but copy mode also works.
	XDPModeNative XDPMode = iota
 
	// XDPModeGeneric means the XDP program runs inside the kernel stack
	// after the packet is already received — no driver support needed.
	// AF_XDP sockets MUST use copy mode here; zero-copy is unavailable.
	XDPModeGeneric
)

func (m XDPMode) String() string {
	if m == XDPModeNative {
		return "native"
	}
	return "generic"
}

type Loader struct {
	objs MasqueXDPObjects
	link link.Link
	mode XDPMode
}

// Load attaches the XDP program to ifaceName.
// Tries native (driver) mode first, falls back to generic (SKB) mode.
func Load(ifaceName string) (*Loader, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return nil, fmt.Errorf("interface %q not found: %w", ifaceName, err)
	}

	objs := MasqueXDPObjects{}
	if err := LoadMasqueXDPObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading XDP objects: %w", err)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.MasqueXdpProg,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err == nil {
		return &Loader{objs: objs, link: l, mode: XDPModeNative}, nil
	}
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
	return &Loader{objs: objs, link: l, mode: XDPModeGeneric}, nil
}

// Mode returns which XDP attach mode is actually in use.
// Pass this to NewConn so it can create AF_XDP sockets with compatible flags.
func (l *Loader) Mode() XDPMode { return l.mode }

// XskMap returns the XSKMAP so AF_XDP sockets can register themselves.
func (l *Loader) XskMap() *ebpf.Map {
	return l.objs.XsksMap
}

// Close detaches the XDP program and frees BPF resources.
func (l *Loader) Close() {
	l.link.Close()
	l.objs.Close()
}
