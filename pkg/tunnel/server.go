//go:build linux

package tunnel

import (
	"bytes"
	"context"
	"crypto/tls"
	goerrors "errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"

	"github.com/alphadose/haxmap"
	"github.com/google/uuid"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/token"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

const (
	tunOffset = device.MessageTransportHeaderSize
)

var (
	connectTmpl = uritemplate.MustNew("https://proxy/connect")

	bufferPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, netstack.IPv6MinMTU+tunOffset)
			return &b
		},
	}

	bytesBufferPool = sync.Pool{
		New: func() interface{} {
			return new(bytes.Buffer)
		},
	}
)

type TunnelOption func(*tunnelOptions)

type tunnelOptions struct {
	tunName   string
	proxyAddr string
	localAddr netip.Prefix
	ulaPrefix netip.Prefix
	certPath  string
	keyPath   string
	ipam      IPAM
}

func defaultOptions() *tunnelOptions {
	return &tunnelOptions{
		tunName:   "tun0",
		proxyAddr: "0.0.0.0:8443",
		localAddr: netip.MustParsePrefix("2001:db8::/64"),
		ulaPrefix: netip.MustParsePrefix("fd00::/64"),
		certPath:  "/etc/apoxy/certs/cert.pem",
		keyPath:   "/etc/apoxy/certs/key.pem",
		ipam:      NewRandomULA(),
	}
}

// WithTUNName sets the name of the TUN interface.
func WithTUNName(name string) TunnelOption {
	return func(o *tunnelOptions) {
		o.tunName = name
	}
}

// WithProxyAddr sets the address to bind the proxy to.
func WithProxyAddr(addr string) TunnelOption {
	return func(o *tunnelOptions) {
		o.proxyAddr = addr
	}
}

// WithLocalAddr sets the local address prefix.
func WithLocalAddr(prefix netip.Prefix) TunnelOption {
	return func(o *tunnelOptions) {
		o.localAddr = prefix
	}
}

// WithULAPrefix sets the Unique Local Address prefix.
func WithULAPrefix(prefix netip.Prefix) TunnelOption {
	return func(o *tunnelOptions) {
		o.ulaPrefix = prefix
	}
}

// WithCertPath sets the path to the TLS certificate.
func WithCertPath(path string) TunnelOption {
	return func(o *tunnelOptions) {
		o.certPath = path
	}
}

// WithKeyPath sets the path to the TLS key.
func WithKeyPath(path string) TunnelOption {
	return func(o *tunnelOptions) {
		o.keyPath = path
	}
}

// WithIPAM sets the IPAM to use.
func WithIPAM(ipam IPAM) TunnelOption {
	return func(o *tunnelOptions) {
		o.ipam = ipam
	}
}

type TunnelServer struct {
	http3.Server
	client.Client

	options *tunnelOptions
	dev     tun.Device
	ln      *quic.EarlyListener

	// Maps tunnel destination address to CONNECT-IP connection.
	tuns *haxmap.Map[string, *connectip.Conn]
	// Maps
	tunnelNodes *haxmap.Map[string, *corev1alpha.TunnelNode]
}

// NewTunnelServer creates a new server proxy that routes traffic via
// QUIC tunnels.
func NewTunnelServer(opts ...TunnelOption) *TunnelServer {
	options := defaultOptions()
	for _, opt := range opts {
		opt(options)
	}

	s := &TunnelServer{
		Server: http3.Server{
			EnableDatagrams: true,
		},
		options:     options,
		tuns:        haxmap.New[string, *connectip.Conn](),
		tunnelNodes: haxmap.New[string, *corev1alpha.TunnelNode](),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/connect/", s.handleConnect)
	s.Handler = mux

	return s
}

func (t *TunnelServer) Start(ctx context.Context, mgr ctrl.Manager) error {
	// 0. Setup TunnelNode controller.
	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
		Complete(reconcile.Func(t.reconcile)); err != nil {
		return fmt.Errorf("failed to start controller: %w", err)
	}

	// 1. Setup QUIC server.
	var err error
	t.dev, err = tun.CreateTUN(t.options.tunName, netstack.IPv6MinMTU)
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %w", err)
	}

	bindTo, err := netip.ParseAddrPort(t.options.proxyAddr)
	if err != nil {
		return fmt.Errorf("failed to parse bind address: %w", err)
	}
	udpConn, err := net.ListenUDP(
		"udp",
		&net.UDPAddr{
			IP:   bindTo.Addr().AsSlice(),
			Port: int(bindTo.Port()),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %w", err)
	}
	defer udpConn.Close()

	cert, err := tls.LoadX509KeyPair(t.options.certPath, t.options.keyPath)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	if t.ln, err = quic.ListenEarly(
		udpConn,
		http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{cert}}),
		&quic.Config{EnableDatagrams: true},
	); err != nil {
		return fmt.Errorf("failed to create QUIC listener: %w", err)
	}

	g, ctx := errgroup.WithContext(context.Background())
	g.Go(func() error {
		g.Go(func() error {
			<-ctx.Done()
			return t.Shutdown(context.Background())
		})

		slog.Info("Starting HTTP/3 server", slog.String("addr", t.ln.Addr().String()))

		return t.ServeListener(t.ln)
	})
	g.Go(func() error {
		g.Go(func() error {
			<-ctx.Done()
			return t.dev.Close()
		})

		slog.Info("Starting TUN muxer")

		return t.mux(ctx)
	})
	return g.Wait()
}

func (t *TunnelServer) Stop(ctx context.Context) error {
	return t.Close()
}

func (t *TunnelServer) handleConnect(w http.ResponseWriter, r *http.Request) {
	slog.Info("Received connection request", slog.String("remote", r.RemoteAddr))

	id, err := uuid.Parse(strings.TrimPrefix(r.URL.Path, "/connect/"))
	if err != nil {
		slog.Error("Failed to parse UUID", slog.Any("error", err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tn, ok := t.tunnelNodes.Get(id.String())
	if !ok {
		slog.Error("Tunnel not found", slog.Any("uuid", id))
		w.WriteHeader(http.StatusNotFound)
		return
	}

	slog.Info("Connection request for UUID", slog.Any("uuid", id))

	authToken := r.URL.Query().Get("token")
	if authToken == "" {
		slog.Error("Missing token in connection request")
		w.WriteHeader(http.StatusForbidden)
		return
	}

	tv, err := token.NewValidator([]byte(tn.Status.Credentials))
	if err != nil {
		slog.Error("Failed to create token validator", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	if err := tv.Validate(authToken, id.String()); err != nil {
		slog.Error("Failed to validate token", slog.Any("error", err))
		w.WriteHeader(http.StatusForbidden)
		return
	}

	slog.Info("Validated token for UUID", slog.Any("uuid", id))

	req, err := connectip.ParseRequest(r, connectTmpl)
	if err != nil {
		slog.Error("Failed to parse request", slog.Any("error", err))
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	p := connectip.Proxy{}
	conn, err := p.Proxy(w, req)
	if err != nil {
		slog.Error("Failed to proxy request", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer conn.Close()

	peerPrefix := t.options.ipam.Allocate(r)
	if err := conn.AssignAddresses(r.Context(), []netip.Prefix{
		peerPrefix,
	}); err != nil {
		slog.Error("Failed to assign address to connection", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}
	if err := conn.AdvertiseRoute(r.Context(), []connectip.IPRoute{
		{
			StartIP: t.options.localAddr.Addr(),
			EndIP:   t.options.localAddr.Addr(),
		},
	}); err != nil {
		slog.Error("Failed to advertise route to connection", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	slog.Info("Client prefix assigned", slog.String("ip", peerPrefix.String()))

	if err := t.addTUNPeer(peerPrefix); err != nil {
		slog.Error("Failed to add TUN peer", slog.Any("error", err))
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(err.Error()))
		return
	}

	t.tuns.Set(peerPrefix.String(), conn)

	go func() {
		b := bufferPool.Get().(*[]byte)
		defer bufferPool.Put(b)

		// TODO (dpeckett): add support for writing batched packets.
		for {
			n, err := conn.ReadPacket((*b)[tunOffset:])
			if err != nil {
				if goerrors.Is(err, net.ErrClosed) {
					slog.Info("Connection closed")
					return
				}
				slog.Error("Failed to read from connection", slog.Any("error", err))
				continue
			}

			slog.Debug("Read from connection", slog.Int("bytes", n))

			if _, err := t.dev.Write([][]byte{(*b)[:n+tunOffset]}, tunOffset); err != nil {
				slog.Error("Failed to write to TUN", slog.Any("error", err))
				continue
			}
		}
	}()

	agent := corev1alpha.AgentStatus{
		Name:           uuid.NewString(),
		ConnectedAt:    ptr.To(metav1.Now()),
		PrivateAddress: peerPrefix.String(),
		AgentAddress:   r.RemoteAddr,
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		upd := &corev1alpha.TunnelNode{}
		if err := t.Get(r.Context(), types.NamespacedName{Name: tn.Name}, upd); errors.IsNotFound(err) {
			slog.Warn("Node not found", slog.String("name", tn.Name))
			return nil
		} else if err != nil {
			slog.Error("Failed to get node", slog.Any("error", err))
			return err
		}

		upd.Status.Agents = append(upd.Status.Agents, agent)

		return t.Status().Update(r.Context(), upd)
	}); err != nil {
		slog.Error("Failed to update agent status", slog.Any("error", err))
	}

	// Blocking wait for the lifetime of the tunnel connection.
	<-r.Context().Done()

	if err := conn.Close(); err != nil {
		slog.Error("Failed to close connection", slog.Any("error", err))
	}

	t.tuns.Del(peerPrefix.String())

	if err := t.options.ipam.Release(peerPrefix); err != nil {
		slog.Error("Failed to deallocate IP address", slog.Any("error", err))
	}

	if err := t.removeTUNPeer(peerPrefix); err != nil {
		slog.Error("Failed to remove TUN peer", slog.Any("error", err))
	}

	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		upd := &corev1alpha.TunnelNode{}
		if err := t.Get(context.Background(), types.NamespacedName{Name: tn.Name}, upd); errors.IsNotFound(err) {
			slog.Warn("Node not found", slog.String("name", tn.Name))
			return nil
		} else if err != nil {
			slog.Error("Failed to get node", slog.Any("error", err))
			return err
		}

		// Find and remove the agent from the status
		for i, a := range upd.Status.Agents {
			if a.Name == agent.Name {
				upd.Status.Agents = append(upd.Status.Agents[:i], upd.Status.Agents[i+1:]...)
				break
			}
		}

		return t.Status().Update(context.Background(), upd)
	}); err != nil {
		slog.Error("Failed to update agent status", slog.Any("error", err))
	}

	slog.Info("Agent removed", slog.String("name", agent.Name))
}

func (t *TunnelServer) addTUNPeer(peer netip.Prefix) error {
	tunName, err := t.dev.Name()
	if err != nil {
		return fmt.Errorf("failed to get TUN interface name: %w", err)
	}
	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return fmt.Errorf("failed to get TUN interface: %w", err)
	}

	slog.Debug("Adding route", slog.String("prefix", peer.String()))

	r := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   peer.Addr().AsSlice(),
			Mask: net.CIDRMask(peer.Bits(), 128),
		},
		Scope: netlink.SCOPE_LINK,
	}
	if err := netlink.RouteAdd(r); err != nil {
		return fmt.Errorf("failed to add route: %w", err)
	}

	return nil
}

func (t *TunnelServer) removeTUNPeer(peer netip.Prefix) error {
	tunName, err := t.dev.Name()
	if err != nil {
		return fmt.Errorf("failed to get TUN interface name: %w", err)
	}
	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return fmt.Errorf("failed to get TUN interface: %w", err)
	}

	slog.Debug("Removing route", slog.String("prefix", peer.String()))

	r := &netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   peer.Addr().AsSlice(),
			Mask: net.CIDRMask(peer.Bits(), 128),
		},
		Scope: netlink.SCOPE_LINK,
	}
	if err := netlink.RouteDel(r); err != nil {
		return fmt.Errorf("failed to remove route: %w", err)
	}

	return nil
}

func (t *TunnelServer) mux(ctx context.Context) error {
	for {
		b := bufferPool.Get().(*[]byte)
		sizes := make([]int, 1)
		_, err := t.dev.Read([][]byte{*b}, sizes, 0)
		if goerrors.Is(err, io.EOF) {
			bufferPool.Put(b)
			return nil
		} else if err != nil {
			bufferPool.Put(b)
			return fmt.Errorf("failed to read from TUN: %w", err)
		}
		slog.Debug("Read packet from TUN", slog.Int("len", sizes[0]))

		var dstIP netip.Addr
		switch (*b)[0] >> 4 {
		case 6:
			// IPv6 packet (RFC 8200)
			if sizes[0] >= 40 {
				var addr [16]byte
				copy(addr[:], (*b)[24:40])
				dstIP = netip.AddrFrom16(addr)
			} else {
				slog.Debug("IPv6 packet too short", slog.Int("length", len(*b)))
				bufferPool.Put(b)
				continue
			}
		default:
			slog.Warn("Unknown packet type (expected IPv6)", slog.String("type", fmt.Sprintf("%#x", (*b)[0]>>4)))
			bufferPool.Put(b)
			continue
		}
		if !dstIP.IsValid() || !dstIP.Is6() || !dstIP.IsGlobalUnicast() {
			slog.Debug("Invalid destination IP", slog.String("ip", dstIP.String()))
			bufferPool.Put(b)
			continue
		}

		slog.Debug("Packet destination", slog.String("ip", dstIP.String()))

		dstPrefix := netip.PrefixFrom(dstIP, 96)
		conn, ok := t.tuns.Get(dstPrefix.String())
		if !ok {
			slog.Debug("No matching tunnel found", slog.String("ip", dstPrefix.String()))
			bufferPool.Put(b)
			continue
		}

		icmp, err := conn.WritePacket((*b)[:sizes[0]])
		bufferPool.Put(b)
		if err != nil {
			slog.Error("Failed to write to connection", slog.Any("error", err))
			continue
		}
		if len(icmp) > 0 {
			slog.Debug("Sending ICMP packet")
			if _, err := t.dev.Write([][]byte{icmp}, 0); err != nil {
				slog.Error("Failed to write ICMP packet", slog.Any("error", err))
			}
		}
	}
	panic("unreachable")
}

func (t *TunnelServer) reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	node := &corev1alpha.TunnelNode{}
	if err := t.Get(ctx, request.NamespacedName, node); errors.IsNotFound(err) {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get TunnelNode: %w", err)
	}

	log := log.FromContext(ctx, "name", node.Name, "uid", node.UID)
	log.Info("Reconciling TunnelNode")

	if !node.DeletionTimestamp.IsZero() {
		log.Info("Deleting TunnelNode")

		// TODO: Send GOAWAY to all connected clients for the associated tunnel node.

		t.tunnelNodes.Del(string(node.UID))
		return reconcile.Result{}, nil
	}

	t.tunnelNodes.Set(string(node.UID), node)

	return ctrl.Result{}, nil
}
