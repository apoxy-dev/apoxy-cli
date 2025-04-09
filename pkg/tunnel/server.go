//go:build linux

package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/alphadose/haxmap"
	"github.com/google/uuid"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/vishvananda/netlink"
	"github.com/yosida95/uritemplate/v3"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/tun"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy-cli/pkg/connip"
	"github.com/apoxy-dev/apoxy-cli/pkg/netstack"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/token"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

var (
	connectTmpl = uritemplate.MustNew("https://proxy/connect")
)

type TunnelServerOption func(*tunnelServerOptions)

type tunnelServerOptions struct {
	tunName   string
	proxyAddr string
	localAddr netip.Prefix
	ulaPrefix netip.Prefix
	certPath  string
	keyPath   string
	ipam      IPAM
	client    client.Client
}

func defaultServerOptions() *tunnelServerOptions {
	return &tunnelServerOptions{
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
func WithTUNName(name string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.tunName = name
	}
}

// WithProxyAddr sets the address to bind the proxy to.
func WithProxyAddr(addr string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.proxyAddr = addr
	}
}

// WithLocalAddr sets the local address prefix.
func WithLocalAddr(prefix netip.Prefix) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.localAddr = prefix
	}
}

// WithULAPrefix sets the Unique Local Address prefix.
func WithULAPrefix(prefix netip.Prefix) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.ulaPrefix = prefix
	}
}

// WithCertPath sets the path to the TLS certificate.
func WithCertPath(path string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.certPath = path
	}
}

// WithKeyPath sets the path to the TLS key.
func WithKeyPath(path string) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.keyPath = path
	}
}

// WithIPAM sets the IPAM to use.
func WithIPAM(ipam IPAM) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.ipam = ipam
	}
}

// WithClient sets the kubernetes client to use.
func WithClient(client client.Client) TunnelServerOption {
	return func(o *tunnelServerOptions) {
		o.client = client
	}
}

type TunnelServer struct {
	http3.Server
	client.Client

	options *tunnelServerOptions
	dev     tun.Device
	ln      *quic.EarlyListener

	// Connections
	mux *connip.MuxedConnection
	// Maps
	tunnelNodes *haxmap.Map[string, *corev1alpha.TunnelNode]

	tunnelCtx       context.Context
	tunnelCtxCancel context.CancelFunc
}

// NewTunnelServer creates a new server proxy that routes traffic via
// QUIC tunnels.
func NewTunnelServer(opts ...TunnelServerOption) *TunnelServer {
	options := defaultServerOptions()
	for _, opt := range opts {
		opt(options)
	}

	s := &TunnelServer{
		Client: options.client,
		Server: http3.Server{
			EnableDatagrams: true,
		},
		options:     options,
		mux:         connip.NewMuxedConnection(),
		tunnelNodes: haxmap.New[string, *corev1alpha.TunnelNode](),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/connect/", s.handleConnect)
	s.Handler = mux

	return s
}

func (t *TunnelServer) SetupWithManager(mgr ctrl.Manager) error {
	t.Client = mgr.GetClient()

	if err := ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
		Complete(reconcile.Func(t.reconcile)); err != nil {
		return fmt.Errorf("failed to start controller: %w", err)
	}

	return nil
}

func (t *TunnelServer) Start(ctx context.Context) error {
	t.tunnelCtx, t.tunnelCtxCancel = context.WithCancel(ctx)

	// TODO (dpeckett): allow creating a userspace netstack based TUN device so
	// that we can more easily test this on non-Linux systems.

	// 1. Setup QUIC server.
	var err error
	t.dev, err = tun.CreateTUN(t.options.tunName, netstack.IPv6MinMTU)
	if err != nil {
		return fmt.Errorf("failed to create TUN interface: %w", err)
	}

	// Bring up the TUN interface.
	tunName, err := t.dev.Name()
	if err != nil {
		return fmt.Errorf("failed to get TUN interface name: %w", err)
	}

	link, err := netlink.LinkByName(tunName)
	if err != nil {
		return fmt.Errorf("failed to get TUN interface: %w", err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed to bring up TUN interface: %w", err)
	}

	// TODO (dpeckett): assign an address from the ULA prefix to the TUN
	// interface.

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

	g, ctx := errgroup.WithContext(t.tunnelCtx)

	g.Go(func() error {
		<-ctx.Done()

		slog.Debug("Closing TUN device")

		if err := t.dev.Close(); err != nil {
			return fmt.Errorf("failed to close TUN device: %w", err)
		}

		slog.Debug("Closing QUIC listener")

		if err := t.Shutdown(context.Background()); err != nil {
			return fmt.Errorf("failed to shutdown QUIC server: %w", err)
		}

		return nil
	})

	g.Go(func() error {
		slog.Info("Starting HTTP/3 server", slog.String("addr", t.ln.Addr().String()))

		return t.ServeListener(t.ln)
	})

	// TODO (dpeckett): Move tun muxing concerns into connip.ServerTransport and use
	// the transport abstraction to handle the tunnel packet shuffling logistics.
	g.Go(func() error {
		slog.Info("Starting TUN muxer")
		defer slog.Debug("TUN muxer stopped")

		return connip.Splice(t.dev, t.mux)
	})

	return g.Wait()
}

func (t *TunnelServer) Stop() error {
	// Stop any background tasks if they are running.
	if t.tunnelCtxCancel != nil {
		t.tunnelCtxCancel()
	}

	return t.Server.Close()
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

	t.mux.AddConnection(peerPrefix, conn)

	agent := corev1alpha.AgentStatus{
		Name:           uuid.NewString(),
		ConnectedAt:    ptr.To(metav1.Now()),
		PrivateAddress: peerPrefix.String(),
		AgentAddress:   r.RemoteAddr,
	}
	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		upd := &corev1alpha.TunnelNode{}
		if err := t.Get(r.Context(), types.NamespacedName{Name: tn.Name}, upd); apierrors.IsNotFound(err) {
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

	if err := conn.Close(); err != nil &&
		!strings.Contains(err.Error(), "close called for canceled stream") {
		slog.Error("Failed to close connection", slog.Any("error", err))
	}

	if err := t.mux.RemoveConnection(peerPrefix); err != nil {
		slog.Error("Failed to remove connection", slog.Any("error", err))
	}

	if err := t.options.ipam.Release(peerPrefix); err != nil {
		slog.Error("Failed to deallocate IP address", slog.Any("error", err))
	}

	if err := t.removeTUNPeer(peerPrefix); err != nil {
		slog.Error("Failed to remove TUN peer", slog.Any("error", err))
	}

	if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		upd := &corev1alpha.TunnelNode{}
		if err := t.Get(context.Background(), types.NamespacedName{Name: tn.Name}, upd); apierrors.IsNotFound(err) {
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

func (t *TunnelServer) reconcile(ctx context.Context, request reconcile.Request) (reconcile.Result, error) {
	node := &corev1alpha.TunnelNode{}
	if err := t.Get(ctx, request.NamespacedName, node); apierrors.IsNotFound(err) {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get TunnelNode: %w", err)
	}

	log := log.FromContext(ctx, "name", node.Name, "uid", node.UID)
	log.Info("Reconciling TunnelNode")

	if !node.DeletionTimestamp.IsZero() {
		log.Info("Deleting TunnelNode")

		// TODO: Send GOAWAY to all connected clients for the associated tunnel node.

		t.RemoveTunnelNode(node)

		return reconcile.Result{}, nil
	}

	t.AddTunnelNode(node)

	return ctrl.Result{}, nil
}

// AddTunnelNode adds a TunnelNode to the server.
// This is visible for testing purposes, it is usually called as part of
// the reconcile loop.
func (t *TunnelServer) AddTunnelNode(node *corev1alpha.TunnelNode) {
	t.tunnelNodes.Set(string(node.UID), node)
}

// RemoveTunnelNode removes a TunnelNode from the server.
// This is visible for testing purposes, it is usually called as part of
// the reconcile loop.
func (t *TunnelServer) RemoveTunnelNode(node *corev1alpha.TunnelNode) {
	t.tunnelNodes.Del(string(node.UID))
}
