package quic
// #cgo CXXFLAGS: -std=c++17 -I${SRCDIR}/../lockfree_mpmc_queue
// #cgo LDFLAGS: -L${SRCDIR}/../lockfree_mpmc_queue -L/usr/lib -lstdc++ -latomic
// #include "queue_wrapper.h"
import "C"
import (
	"context"
	"unsafe"
	"sync"
	"runtime"
	
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/internal/wire"
)

const (
	maxDatagramSendQueueLen = 32
	maxDatagramRcvQueueLen  = 128
)

var dataPool = sync.Pool{
	New: func() any {
		b := make([]byte, 1500)
		return &b
	},
}

type datagramQueue struct {
	sendQueue unsafe.Pointer
	sent      chan struct{} // used to notify Add that a datagram was dequeued

	rcvQueue unsafe.Pointer
	rcvd     chan struct{} // used to notify Receive that a new datagram was received

	pinners   sync.Map

	closeErr error
	closed   chan struct{}

	hasData func()

	logger utils.Logger
}

func newDatagramQueue(hasData func(), logger utils.Logger) *datagramQueue {
	q := &datagramQueue{
		sendQueue: unsafe.Pointer(C.queue_new(C.int(maxDatagramSendQueueLen))),
		rcvQueue:  unsafe.Pointer(C.queue_new(C.int(maxDatagramRcvQueueLen))),
		hasData: hasData,
		rcvd:    make(chan struct{}, 1),
		sent:    make(chan struct{}, 1),
		closed:  make(chan struct{}),
		logger:  logger,
	}
	runtime.SetFinalizer(q, func(q *datagramQueue) {
        C.queue_free(q.sendQueue)
        C.queue_free(q.rcvQueue)
    })
    return q
}

// Add queues a new DATAGRAM frame for sending.
// Up to 32 DATAGRAM frames will be queued.
// Once that limit is reached, Add blocks until the queue size has reduced.
func (h *datagramQueue) Add(f *wire.DatagramFrame) error {
	p := new(runtime.Pinner)
    p.Pin(f)
    p.Pin(&f.Data)  // pin the slice header's backing array reference
	for {
		if C.queue_push(h.sendQueue, unsafe.Pointer(f)) == 1 {
		    h.pinners.Store(uintptr(unsafe.Pointer(f)), p)
    		// CloseWithError may have drained before Store — self-cleanup
    		select {
    			case <-h.closed:
        			if v, ok := h.pinners.LoadAndDelete(uintptr(unsafe.Pointer(f))); ok {
            			v.(*runtime.Pinner).Unpin()
        			}
        			return h.closeErr
    			default:
        			h.hasData()
        			return nil
    		}
		}
		// queue full, wait for Pop to signal
		select {
		case <-h.closed:
			p.Unpin()
			return h.closeErr
		case <-h.sent:
		}
	}
}

// Peek gets the next DATAGRAM frame for sending.
// If actually sent out, Pop needs to be called before the next call to Peek.
func (h *datagramQueue) Peek() *wire.DatagramFrame {
	var out unsafe.Pointer
	if C.queue_peek(h.sendQueue, &out) == 0 {
		return nil
	}
	return (*wire.DatagramFrame)(out)
}

func (h *datagramQueue) Pop() {
	var out unsafe.Pointer
	C.queue_pop(h.sendQueue, &out)
	if v, ok := h.pinners.LoadAndDelete(uintptr(out)); ok {
        v.(*runtime.Pinner).Unpin()
    }
	select {
	case h.sent <- struct{}{}:
	default:
	}
}

// HandleDatagramFrame handles a received DATAGRAM frame.
func (h *datagramQueue) HandleDatagramFrame(f *wire.DatagramFrame) {
	select {
    	case <-h.closed:
        	return  // connection already closed, drop it
    	default:
    }
	bufp := dataPool.Get().(*[]byte)
    if cap(*bufp) < len(f.Data) {
        *bufp = make([]byte, len(f.Data))
    }
    *bufp = (*bufp)[:len(f.Data)]
    copy(*bufp, f.Data)
	p := new(runtime.Pinner)
    p.Pin(bufp)
	if C.queue_push(h.rcvQueue, unsafe.Pointer(bufp)) == 1 {
    	h.pinners.Store(uintptr(unsafe.Pointer(bufp)), p)
    	// CloseWithError may have drained before Store — self-cleanup
    	select {
    		case <-h.closed:
        		if v, ok := h.pinners.LoadAndDelete(uintptr(unsafe.Pointer(bufp))); ok {
            		v.(*runtime.Pinner).Unpin()
        		}
        		dataPool.Put(bufp)
        		return
    		default:
        		select {
        			case h.rcvd <- struct{}{}:
        			default:
        		}
    	}
	} else {
    	p.Unpin()
    	dataPool.Put(bufp)
    	if h.logger.Debug() {
        	h.logger.Debugf("Discarding received DATAGRAM frame (%d bytes payload)", len(f.Data))
    	}
	}
}

// Receive gets a received DATAGRAM frame.
func (h *datagramQueue) Receive(ctx context.Context) ([]byte, error) {
	for {
		var out unsafe.Pointer
		if C.queue_pop(h.rcvQueue, &out) == 1 {
			bufp := (*[]byte)(out)
            if v, ok := h.pinners.LoadAndDelete(uintptr(out)); ok {
                v.(*runtime.Pinner).Unpin()
            }
            return *bufp, nil
		}
		select {
		case <-h.rcvd:
			continue
		case <-h.closed:
			return nil, h.closeErr
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

func (h *datagramQueue) CloseWithError(e error) {
	h.closeErr = e
    close(h.closed) // signal first, THEN drain
    // drain send queue and unpin
    var out unsafe.Pointer
    for C.queue_pop(h.sendQueue, &out) == 1 {
        if v, ok := h.pinners.LoadAndDelete(uintptr(out)); ok {
            v.(*runtime.Pinner).Unpin()
        }
    }

    // drain receive queue and unpin
    for C.queue_pop(h.rcvQueue, &out) == 1 {
        if v, ok := h.pinners.LoadAndDelete(uintptr(out)); ok {
            v.(*runtime.Pinner).Unpin()
        }
        // also return the buffer to the pool
        dataPool.Put((*[]byte)(out))
    }
}
