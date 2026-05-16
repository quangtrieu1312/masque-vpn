//go:build linux

package utility

import (
    "errors"
    "fmt"
    "unsafe"
	"syscall"
	"sync/atomic"

    "golang.org/x/net/ipv4"
    "golang.org/x/net/ipv6"
    "golang.org/x/sys/unix"
)

const MaxBatchSize = 1024

var totalFlushes atomic.Int64
var totalPackets atomic.Int64

type mmsghdr struct {
	Hdr unix.Msghdr
	Len uint32
	_   [4]byte
}

type SocketBatch struct {
    fd     int
    msgs   []mmsghdr
    iovs   []unix.Iovec
    addrs4 []unix.RawSockaddrInet4
    addrs6 []unix.RawSockaddrInet6
    bufs   [MaxBatchSize][1500]byte
    count  int
}

func IPVersion(b []byte) uint8 {
    return b[0] >> 4
}


func NewSocketBatch(fd int) *SocketBatch {
    return &SocketBatch{
        fd:     fd,
        msgs:   make([]mmsghdr, MaxBatchSize),
        iovs:   make([]unix.Iovec, MaxBatchSize),
        addrs4: make([]unix.RawSockaddrInet4, MaxBatchSize),
        addrs6: make([]unix.RawSockaddrInet6, MaxBatchSize),
    }
}

func (b *SocketBatch) Add(pkt []byte) error {
	i := b.count
    n := copy(b.bufs[i][:], pkt)
    switch v := IPVersion(pkt); v {
    case 4:
        if len(pkt) < ipv4.HeaderLen {
            return errors.New("IPv4 packet too short")
        }
        i := b.count
        b.addrs4[i] = unix.RawSockaddrInet4{
            Family: unix.AF_INET,
            Addr:   ([4]byte)(pkt[16:20]),
        }
        b.iovs[i] = unix.Iovec{Base: &b.bufs[i][0]}
        b.iovs[i].SetLen(n)
        b.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&b.addrs4[i]))
        b.msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet4
        b.msgs[i].Hdr.Iov = &b.iovs[i]
        b.msgs[i].Hdr.SetIovlen(1)
        b.count++
        return nil
    case 6:
        if len(pkt) < ipv6.HeaderLen {
            return errors.New("IPv6 packet too short")
        }
        i := b.count
        b.addrs6[i] = unix.RawSockaddrInet6{
            Family: unix.AF_INET6,
            Addr:   ([16]byte)(pkt[24:40]),
        }
        b.iovs[i] = unix.Iovec{Base: &pkt[0]}
        b.iovs[i].SetLen(len(pkt))
        b.msgs[i].Hdr.Name = (*byte)(unsafe.Pointer(&b.addrs6[i]))
        b.msgs[i].Hdr.Namelen = unix.SizeofSockaddrInet6
        b.msgs[i].Hdr.Iov = &b.iovs[i]
        b.msgs[i].Hdr.SetIovlen(1)
        b.count++
        return nil
    default:
        return fmt.Errorf("unknown IP version: %d", v)
    }
}

func (b *SocketBatch) Flush() error {
	if b.count == 0 {
        return nil
    }
    _, _, errno := syscall.Syscall6(
        unix.SYS_SENDMMSG,
        uintptr(b.fd),
        uintptr(unsafe.Pointer(&b.msgs[0])),
        uintptr(b.count),
        uintptr(unix.MSG_DONTWAIT),
        0, 0,
    )
    b.count = 0
	totalFlushes.Add(1)
	totalPackets.Add(int64(b.count))
    if errno != 0 {
        return errno
    }
    return nil

}

func (b *SocketBatch) Full() bool {
    return b.count >= MaxBatchSize
}

// SendOnSocket kept for backward compat / single packet fallback
func SendOnSocket(fd int, pkt []byte) error {
    b := NewSocketBatch(fd)
    if err := b.Add(pkt); err != nil {
        return err
    }
    return b.Flush()
}

func BatchStats() (flushes, packets int64, avg float64) {
    f := totalFlushes.Load()
    p := totalPackets.Load()
    if f == 0 {
        return f, p, 0
    }
    return f, p, float64(p) / float64(f)
}
