package wireguard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/pion/ice/v4"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

const maxMessageSize = 65535

type IceBind struct {
	conf    *ice.AgentConfig
	pCtx    context.Context
	ctx     context.Context
	cancel  context.CancelFunc
	recvCh  chan *message
	mu      sync.RWMutex
	peers   map[string]*IcePeer
	msgPool sync.Pool
}

// NewIceBind creates a new IceBind.
func NewIceBind(ctx context.Context, conf *ice.AgentConfig) *IceBind {
	return &IceBind{
		conf:   conf,
		pCtx:   ctx,
		recvCh: make(chan *message, 1000),
		peers:  make(map[string]*IcePeer),
		msgPool: sync.Pool{
			New: func() interface{} {
				return &message{
					buf: make([]byte, maxMessageSize),
				}
			},
		},
	}
}

func (b *IceBind) Close() error {
	log.Debugf("Closing IceBind")
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ep := range b.peers {
		ep.agent.Close()
	}
	clear(b.peers)
	if b.cancel != nil {
		b.cancel()
		b.cancel = nil
	}
	return nil
}

type message struct {
	buf []byte
	dst string
}

func (b *IceBind) Open(_ uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	log.Debugf("Opening")

	// Create a new context for each Open() call.
	b.ctx, b.cancel = context.WithCancel(b.pCtx)

	return []conn.ReceiveFunc{func(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-b.ctx.Done():
			log.Debugf("bind.Open() closed")
			return 0, net.ErrClosed
		case msg := <-b.recvCh:
			copy(pkts[0], msg.buf)
			sizes[0] = len(msg.buf)
			eps[0] = &endpoint{dst: msg.dst}

			msg.buf = msg.buf[:maxMessageSize] // Reset the buffer to its original capacity.
			b.msgPool.Put(msg)

			return 1, nil
		}
	}}, 0, nil
}

func (b *IceBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	return &endpoint{
		dst: s,
	}, nil
}

func (b *IceBind) Send(bufs [][]byte, ep conn.Endpoint) error {
	iceEp, ok := ep.(*endpoint)
	if !ok {
		return fmt.Errorf("invalid endpoint type: %T", ep)
	}
	b.mu.RLock()
	peer, ok := b.peers[iceEp.dst]
	if !ok {
		b.mu.RUnlock()
		return fmt.Errorf("endpoint with dst %q not connected", iceEp.dst)
	}
	b.mu.RUnlock()
	for _, buf := range bufs {
		if _, err := peer.c.Write(buf); err != nil {
			log.Errorf("Failed to write to peer %v: %v", peer, err)
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
	OnCandidate            func(candidate string)
	OnConnected            func()
	OnDisconnected         func(msg string)
	OnCandidatePair        func(local, remote string)
	bind                   *IceBind
	agent                  *ice.Agent
	ufrag, password        string
	isControlling          bool
	remoteUfrag, remotePwd string
	dst                    string
	c                      *ice.Conn
	candMu                 sync.RWMutex
	candidates             []string
}

func (b *IceBind) NewPeer(isControlling bool) (*IcePeer, error) {
	agent, err := ice.NewAgent(b.conf)
	if err != nil {
		return nil, fmt.Errorf("could not create ICE agent: %w", err)
	}

	ufrag, pwd, err := agent.GetLocalUserCredentials()
	if err != nil {
		return nil, fmt.Errorf("could not get local user credentials: %w", err)
	}

	return &IcePeer{
		bind:          b,
		agent:         agent,
		ufrag:         ufrag,
		password:      pwd,
		isControlling: isControlling,
	}, nil
}

func (p *IcePeer) Init() error {
	if err := p.agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		p.candMu.Lock()
		p.candidates = append(p.candidates, c.Marshal())
		p.candMu.Unlock()

		if p.OnCandidate != nil {
			p.OnCandidate(c.Marshal())
		}
	}); err != nil {
		return fmt.Errorf("could not set ICE candidate handler: %w", err)
	}

	if err := p.agent.OnConnectionStateChange(func(c ice.ConnectionState) {
		log.Debugf("ICE connection state: %v", c)
		switch c {
		case ice.ConnectionStateConnected:
			if p.OnConnected != nil {
				p.OnConnected()
			}
		case ice.ConnectionStateDisconnected, ice.ConnectionStateFailed:
			if p.OnDisconnected != nil {
				p.OnDisconnected(c.String())
			}
		}
	}); err != nil {
		return fmt.Errorf("could not set ICE connection state handler: %w", err)
	}

	if err := p.agent.OnSelectedCandidatePairChange(func(local, remote ice.Candidate) {
		log.Debugf("ICE selected candidate pair: %v, %v", local, remote)

		if p.OnCandidatePair != nil {
			p.OnCandidatePair(local.Marshal(), remote.Marshal())
		}
	}); err != nil {
		return fmt.Errorf("could not set ICE selected candidate pair handler: %w", err)
	}

	if err := p.agent.GatherCandidates(); err != nil {
		return fmt.Errorf("could not gather ICE candidates: %w", err)
	}

	return nil
}

func (p *IcePeer) LocalUserCredentials() (ufrag, pwd string) {
	return p.ufrag, p.password
}

func (p *IcePeer) LocalCandidates() []string {
	p.candMu.RLock()
	defer p.candMu.RUnlock()
	return append([]string(nil), p.candidates...)
}

func (p *IcePeer) AddRemoteOffer(offer *corev1alpha.ICEOffer) error {
	p.remoteUfrag, p.remotePwd = offer.Ufrag, offer.Password
	for _, c := range offer.Candidates {
		rc, err := ice.UnmarshalCandidate(c)
		if err != nil {
			return fmt.Errorf("could not unmarshal remote candidate: %w", err)
		}
		if err := p.agent.AddRemoteCandidate(rc); err != nil {
			return fmt.Errorf("could not add remote candidate: %w", err)
		}
	}
	return nil
}

func (p *IcePeer) Connect(
	ctx context.Context,
	dst string,
) error {
	log.Infof("Connecting to %s", dst)
	var (
		err error
		c   *ice.Conn
	)
	if p.isControlling {
		log.Debugf("Dialing to ICE remote peer %s", dst)
		c, err = p.agent.Dial(ctx, p.remoteUfrag, p.remotePwd)
	} else {
		log.Debugf("Accepting connection from ICE remote peer %s", dst)
		c, err = p.agent.Accept(ctx, p.remoteUfrag, p.remotePwd)
	}
	if err != nil {
		return err
	}
	p.c = c

	log.Debugf("ICE connection established for peer %v", p)

	p.bind.mu.Lock()
	p.bind.peers[dst] = p
	p.bind.mu.Unlock()
	p.dst = dst

	go func() {
		defer p.c.Close()
		for {
			msg := p.bind.msgPool.Get().(*message)
			n, err := p.c.Read(msg.buf)
			if err != nil {
				if !errors.Is(err, ice.ErrClosed) {
					log.Debugf("ICE connection closed for peer %v: %v", p, err)
				} else {
					log.Errorf("Error reading from ICE connection: %v", err)
				}
				return
			}
			if n == 0 {
				continue
			}

			msg.buf = msg.buf[:n]
			msg.dst = dst

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
	p.agent.Close()
	p.bind.mu.Lock()
	delete(p.bind.peers, p.dst)
	p.bind.mu.Unlock()
	return nil
}

type endpoint struct {
	dst string
}

func (e *endpoint) DstToString() string {
	return e.dst
}

func (e *endpoint) SrcToString() string {
	return ""
}

func (e *endpoint) ClearSrc() {}

func (e *endpoint) DstToBytes() []byte {
	return []byte(e.dst)
}

func (e *endpoint) DstIP() netip.Addr {
	return netip.Addr{} // not used
}

func (e *endpoint) SrcIP() netip.Addr {
	return netip.Addr{} // not used
}
