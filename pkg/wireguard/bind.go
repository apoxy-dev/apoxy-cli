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

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

type IceBind struct {
	Conf *ice.AgentConfig

	pctx      context.Context
	ctx       context.Context
	ctxCancel context.CancelFunc

	recvCh chan *message

	mu    sync.RWMutex
	peers map[string]*IcePeer

	msgPool sync.Pool
}

const (
	maxMessageSize = 65535
)

// NewIceBind creates a new IceBind.
func NewIceBind(ctx context.Context, conf *ice.AgentConfig) *IceBind {
	cctx, ctxCancel := context.WithCancel(ctx)
	return &IceBind{
		Conf: conf,

		pctx:      ctx,
		ctx:       cctx,
		ctxCancel: ctxCancel,

		recvCh: make(chan *message, 1000),

		peers: make(map[string]*IcePeer),

		msgPool: sync.Pool{
			New: func() interface{} {
				return &message{
					buf: make([]byte, maxMessageSize),
					ep:  &endpoint{},
				}
			},
		},
	}
}

func (b *IceBind) Close() error {
	log.Debugf("Closing")
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, ep := range b.peers {
		ep.agent.Close()
	}
	clear(b.peers)
	//b.ctxCancel()
	//b.ctx, b.ctxCancel = context.WithCancel(b.ctx)
	return nil
}

type message struct {
	buf []byte
	ep  conn.Endpoint
}

func (b *IceBind) Open(port uint16) (fns []conn.ReceiveFunc, actualPort uint16, err error) {
	log.Debugf("Opening port %d", port)
	return []conn.ReceiveFunc{func(pkts [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		select {
		case <-b.ctx.Done():
			log.Errorf("bind.Open() closed")
			return 0, net.ErrClosed
		case msg := <-b.recvCh:
			copy(pkts[0], msg.buf)
			sizes[0] = len(msg.buf)
			eps[0] = msg.ep

			log.Debugf("Received message from %v of size %d", msg.ep, len(msg.buf))

			msg.buf = msg.buf[:maxMessageSize] // Reset the buffer to its original capacity.
			b.msgPool.Put(msg)

			return 1, nil
		}
	}}, port, nil
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
		log.Debugf("Writing buf of size %d to peer %v", len(buf), peer)
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
	OnCandidate func(candidate string)

	ufrag, password        string
	isControlling          bool
	remoteUfrag, remotePwd string
	dst                    string

	bind  *IceBind
	agent *ice.Agent
	c     *ice.Conn

	candMu     sync.RWMutex
	candidates []string
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

	return &IcePeer{
		ufrag:         ufrag,
		password:      pwd,
		isControlling: isControlling,
		bind:          b,
		agent:         agent,
	}, nil
}

func (p *IcePeer) Init(ctx context.Context) error {
	if err := p.agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			return
		}
		log.Debugf("ICE candidate: %v", c)
		p.candMu.Lock()
		p.candidates = append(p.candidates, c.Marshal())
		p.candMu.Unlock()
		p.OnCandidate(c.Marshal())
	}); err != nil {
		return fmt.Errorf("could not set ICE candidate handler: %w", err)
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
	connCh := make(chan struct{})
	if err := p.agent.OnConnectionStateChange(func(c ice.ConnectionState) {
		log.Debugf("ICE connection state: %v", c)
		if c == ice.ConnectionStateConnected {
			close(connCh)
		}
	}); err != nil {
		return err
	}

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

	select {
	case <-connCh:
		log.Infof("ICE connection established for peer %v", p)
	case <-ctx.Done():
		return ctx.Err()
	}

	p.bind.mu.Lock()
	p.bind.peers[dst] = p
	p.bind.mu.Unlock()
	p.dst = dst

	go func() {
		defer p.c.Close()
		for {
			msg := p.bind.msgPool.Get().(*message)
			log.Debugf("Got buf of size %d from pool", len(msg.buf))
			n, err := p.c.Read(msg.buf)
			if err != nil {
				if err != ice.ErrClosed {
					log.Errorf("Error reading from ICE connection: %v", err)
				}
				log.Infof("ICE connection closed for peer %v: %v", p, err)
				return
			}
			if n == 0 {
				continue
			}

			log.Debugf("Received %d bytes from ICE connection", n)

			msg.buf = msg.buf[:n]
			msg.ep.(*endpoint).dst = dst

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
