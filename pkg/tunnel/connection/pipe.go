package connection

import (
	"context"
	"errors"
	"runtime"
	"sync"

	"github.com/hedzr/go-ringbuf/v2"
	"github.com/hedzr/go-ringbuf/v2/mpmc"
)

var _ Connection = (*Pipe)(nil)

type Pipe struct {
	readRing  mpmc.RingBuffer[[]byte]
	writeRing mpmc.RingBuffer[[]byte]
	ctx       context.Context
	cancel    context.CancelFunc
}

var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 2048) // Adjust size if needed
		return &b
	},
}

// NewPipe creates a pair of connected Pipe instances for bidirectional communication.
func NewPipe(ctx context.Context) (*Pipe, *Pipe) {
	ringAtoB := ringbuf.New[[]byte](1024)
	ringBtoA := ringbuf.New[[]byte](1024)

	ctx, cancel := context.WithCancel(ctx)

	pipeA := &Pipe{
		readRing:  ringBtoA,
		writeRing: ringAtoB,
		ctx:       ctx,
		cancel:    cancel,
	}
	pipeB := &Pipe{
		readRing:  ringAtoB,
		writeRing: ringBtoA,
		ctx:       ctx,
		cancel:    cancel,
	}

	return pipeA, pipeB
}

// ReadPacket reads a packet into the provided buffer.
func (p *Pipe) ReadPacket(buf []byte) (int, error) {
	select {
	case <-p.ctx.Done():
		return 0, errors.New("pipe closed")
	default:
		var item []byte
		var err error
		for {
			item, err = p.readRing.Dequeue()
			if err != nil {
				if errors.Is(err, mpmc.ErrQueueEmpty) {
					runtime.Gosched()

					// Has the context been cancelled?
					select {
					case <-p.ctx.Done():
						bufPool.Put(&item)
						return 0, errors.New("pipe closed")
					default:
						// Continue to try to dequeue
						continue
					}
				}
				return 0, err
			}
			break
		}
		n := copy(buf, item)
		bufPool.Put(&item)
		return n, nil
	}
}

// WritePacket writes a packet from the provided buffer.
func (p *Pipe) WritePacket(b []byte) ([]byte, error) {
	select {
	case <-p.ctx.Done():
		return nil, errors.New("pipe closed")
	default:
		bufPtr := bufPool.Get().(*[]byte)
		buf := *bufPtr
		if cap(buf) < len(b) {
			buf = make([]byte, len(b))
		}
		buf = buf[:len(b)]
		copy(buf, b)

		for {
			err := p.writeRing.Enqueue(buf)
			if err != nil {
				if errors.Is(err, mpmc.ErrQueueFull) {
					runtime.Gosched()

					// Has the context been cancelled?
					select {
					case <-p.ctx.Done():
						bufPool.Put(&buf)
						return nil, errors.New("pipe closed")
					default:
						// Continue to try to enqueue
						continue
					}
				}
				return nil, err
			}
			break
		}

		return nil, nil
	}
}

// Close terminates the pipe.
func (p *Pipe) Close() error {
	p.cancel()
	return nil
}
