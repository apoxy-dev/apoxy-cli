package wireguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/pion/ice/v4"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

type IceBind struct {
	Conf *ice.AgentConfig

	ctx       context.Context
	ctxCancel context.CancelFunc

	recvCh chan *message

	epMu sync.RWMutex
	eps  map[string]*IcePeer

	bufPool sync.Pool
	msgPool sync.Pool
}

// NewIceBind creates a new IceBind.
func NewIceBind(ctx context.Context, conf *ice.AgentConfig) *IceBind {
	ctx, ctxCancel := context.WithCancel(ctx)
	return &IceBind{
		Conf: conf,

		ctx:       ctx,
		ctxCancel: ctxCancel,

		recvCh: make(chan *message),

		eps: make(map[string]*IcePeer),

		bufPool: sync.Pool{
			New: func() interface{} {
				buf := make([]byte, 1500)
				return &buf
			},
		},
		msgPool: sync.Pool{
			New: func() interface{} {
				return &message{}
			},
		},
	}
}

func (b *IceBind) Close() error {
	b.epMu.Lock()
	defer b.epMu.Unlock()
	for _, ep := range b.eps {
		ep.c.Close()
		ep.agent.Close()
	}
	clear(b.eps)
	b.ctxCancel()
	return nil
}

type message struct {
	buf []byte
	ep  conn.Endpoint
}

func (b *IceBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	return []conn.ReceiveFunc{func(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-b.ctx.Done():
			return 0, net.ErrClosed
		case msg := <-b.recvCh:
			copy(pkts[0], msg.buf)
			sizes[0] = len(msg.buf)
			eps[0] = msg.ep

			b.bufPool.Put(&msg.buf)
			b.msgPool.Put(&msg)

			return 1, nil
		}
	}}, port, nil
}

func (b *IceBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &endpoint{
		ufrag: s,
	}, nil
}

func (b *IceBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	iceEp, ok := ep.(*endpoint)
	if !ok {
		return fmt.Errorf("invalid endpoint type: %T", ep)
	}
	b.epMu.RLock()
	peer, ok := b.eps[iceEp.ufrag]
	if !ok {
		b.epMu.RUnlock()
		return fmt.Errorf("endpoint with ufrag %q not connected", iceEp.ufrag)
	}
	b.epMu.RUnlock()
	for _, buf := range bufs {
		if _, err := peer.c.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *IceBind) SetMark(mark uint32) error {
	return nil
}

func (b *IceBind) BatchSize() int { return 1 }

type IcePeer struct {
	ufrag, password string
	isControlling   bool

	bind  *IceBind
	agent *ice.Agent
	c     *ice.Conn
}

func (b *IceBind) NewPeer(ctx context.Context, isControlling bool) (*IcePeer, error) {
	agent, err := ice.NewAgent(b.Conf)
	if err != nil {
		return nil, fmt.Errorf("could not create ICE agent: %w", err)
	}
	ufrag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("could not get local user credentials: %w", err)
	}
	if err := agent.GatherCandidates(); err != nil {
		return nil, fmt.Errorf("could not gather ICE candidates: %w", err)
	}

	b.epMu.Lock()
	defer b.epMu.Unlock()
	b.eps[ufrag] = &IcePeer{
		ufrag:         ufrag,
		password:      pwd,
		isControlling: isControlling,
		bind:          b,
		agent:         agent,
	}
	return b.eps[ufrag], nil
}

func (p *IcePeer) LocalUserCredentials() (ufrag, pwd string) {
	return p.ufrag, p.password
}

func (p *IcePeer) LocalCandidates() ([]string, error) {
	cs, err := p.agent.GetLocalCandidates()
	if err != nil {
		return nil, fmt.Errorf("could not get local candidates: %w", err)
	}
	var ss []string
	for _, c := range cs {
		ss = append(ss, c.String())
	}
	return ss, nil
}

func (p *IcePeer) Connect(
	ctx context.Context,
	ufrag, pwd string,
	remoteCandidates []string,
) error {
	connCh := make(chan struct{})
	if err := p.agent.OnConnectionStateChange(func(c ice.ConnectionState) {
		if c == ice.ConnectionStateConnected {
			close(connCh)
		}
	}); err != nil {
		return err
	}
	for _, c := range remoteCandidates {
		rc, err := ice.UnmarshalCandidate(c)
		if err != nil {
			return fmt.Errorf("could not unmarshal remote candidate: %w", err)
		}
		if err := p.agent.AddRemoteCandidate(rc); err != nil {
			return fmt.Errorf("could not add remote candidate: %w", err)
		}
	}
	select {
	case <-connCh:
		log.Infof("ICE connection established for peer %v", p)
	case <-ctx.Done():
		return ctx.Err()
	}

	var err error
	if p.isControlling {
		p.c, err = p.agent.Accept(ctx, p.ufrag, p.password)
	} else {
		p.c, err = p.agent.Dial(ctx, p.ufrag, p.password)
	}
	if err != nil {
		return err
	}

	go func() {
		defer p.c.Close()
		for {
			buf := p.bind.bufPool.Get().(*[]byte)
			n, err := p.c.Read(*buf)
			if err != nil {
				if err != ice.ErrClosed {
					log.Errorf("Error reading from ICE connection: %v", err)
				}
				return
			}
			if n == 0 {
				continue
			}

			msg := p.bind.msgPool.Get().(*message)
			msg.buf = (*buf)[:n]
			msg.ep = &endpoint{
				ufrag: p.ufrag,
			}

			select {
			case p.bind.recvCh <- msg:
			case <-p.bind.ctx.Done():
				return
			}
		}
	}()

	return nil
}

func (p *IcePeer) Close() error {
	p.c.Close()
	p.agent.Close()
	p.bind.epMu.Lock()
	delete(p.bind.eps, p.ufrag)
	p.bind.epMu.Unlock()
	return nil
}

type endpoint struct {
	ufrag string
}

func (e *endpoint) DstToString() string {
	return e.ufrag
}

func (e *endpoint) SrcToString() string {
	return ""
}

func (e *endpoint) ClearSrc() {}

func (e *endpoint) DstToBytes() []byte {
	return []byte(e.ufrag)
}

func (e *endpoint) DstIP() netip.Addr {
	return netip.Addr{} // not used
}

func (e *endpoint) SrcIP() netip.Addr {
	return netip.Addr{} // not used
}
