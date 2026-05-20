//go:build linux

package xdp

import (
	"fmt"
	"path/filepath"
)

// QueueInfo holds the active (soft-limit) RX and TX queue counts
// for a NIC, as reported by sysfs. These are what AF_XDP can bind to.
// To raise these, run: ethtool -L <iface> combined N
// To see the hardware ceiling, run: ethtool -l <iface>
type QueueInfo struct {
	RX int
	TX int
}

// GetQueueInfo reads the active RX and TX queue counts for ifaceName
// from /sys/class/net/<iface>/queues/. This reflects the current soft
// limit — the value you set with `ethtool -L`. It is always ≤ the
// hardware maximum reported by `ethtool -l`.
//
// AF_XDP bind() will fail with EINVAL for any queue_id ≥ RX count,
// so always use this (not runtime.NumCPU()) as the upper bound.
func GetQueueInfo(ifaceName string) (QueueInfo, error) {
	base := filepath.Join("/sys/class/net", ifaceName, "queues")

	rxMatches, err := filepath.Glob(filepath.Join(base, "rx-*"))
	if err != nil {
		return QueueInfo{}, fmt.Errorf("reading RX queues for %s: %w", ifaceName, err)
	}
	txMatches, err := filepath.Glob(filepath.Join(base, "tx-*"))
	if err != nil {
		return QueueInfo{}, fmt.Errorf("reading TX queues for %s: %w", ifaceName, err)
	}

	info := QueueInfo{RX: len(rxMatches), TX: len(txMatches)}

	if info.RX == 0 {
		// sysfs unavailable (e.g. veth in some kernels) — safe fallback
		info.RX = 1
	}
	if info.TX == 0 {
		info.TX = 1
	}

	return info, nil
}
