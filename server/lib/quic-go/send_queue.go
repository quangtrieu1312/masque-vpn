package quic

import (
	"net"

	"github.com/quic-go/quic-go/internal/protocol"
)

type sender interface {
	Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN)
	SendProbe(*packetBuffer, net.Addr, packetInfo)
	Run() error
	WouldBlock() bool
	Available() <-chan struct{}
	Close()
}

type queueEntry struct {
	buf     *packetBuffer
	gsoSize uint16
	ecn     protocol.ECN
}

type sendQueue struct {
	queue       chan queueEntry
	closeCalled chan struct{} // runStopped when Close() is called
	runStopped  chan struct{} // runStopped when the run loop returns
	available   chan struct{}
	conn        sendConn
}

var _ sender = &sendQueue{}

const sendQueueCapacity = 64

func newSendQueue(conn sendConn) sender {
	return &sendQueue{
		conn:        conn,
		runStopped:  make(chan struct{}),
		closeCalled: make(chan struct{}),
		available:   make(chan struct{}, 1),
		queue:       make(chan queueEntry, sendQueueCapacity),
	}
}

// Send sends out a packet. It's guaranteed to not block.
// Callers need to make sure that there's actually space in the send queue by calling WouldBlock.
// Otherwise Send will panic.
func (h *sendQueue) Send(p *packetBuffer, gsoSize uint16, ecn protocol.ECN) {
	select {
	case h.queue <- queueEntry{buf: p, gsoSize: gsoSize, ecn: ecn}:
		// clear available channel if we've reached capacity
		if len(h.queue) == sendQueueCapacity {
			select {
			case <-h.available:
			default:
			}
		}
	case <-h.runStopped:
	default:
		panic("sendQueue.Send would have blocked")
	}
}

func (h *sendQueue) SendProbe(p *packetBuffer, addr net.Addr, info packetInfo) {
	h.conn.WriteTo(p.Data, addr, info)
}

func (h *sendQueue) WouldBlock() bool {
	return len(h.queue) == sendQueueCapacity
}

func (h *sendQueue) Available() <-chan struct{} {
	return h.available
}

func (h *sendQueue) Run() error {
    defer close(h.runStopped)
    batch := make([]queueEntry, 0, sendQueueCapacity)
    var shouldClose bool
    for {
        if shouldClose && len(h.queue) == 0 {
            return nil
        }
        // Block on first entry
        select {
        case <-h.closeCalled:
            h.closeCalled = nil
            shouldClose = true
            continue
        case e := <-h.queue:
            batch = append(batch, e)
        }
        // Drain remainder non-blocking
        drainLoop:
        for len(batch) < sendQueueCapacity {
            select {
            case e := <-h.queue:
                batch = append(batch, e)
            default:
                break drainLoop
            }
        }
        // Single batch write
        if err := h.conn.WriteBatch(batch); err != nil {
            if !isSendMsgSizeErr(err) {
                return err
            }
        }
        for i := range batch {
            batch[i].buf.Release()
            batch[i] = queueEntry{}
        }
        batch = batch[:0]
        select {
        case h.available <- struct{}{}:
        default:
        }
    }
}

func (h *sendQueue) Close() {
	close(h.closeCalled)
	// wait until the run loop returned
	<-h.runStopped
}
