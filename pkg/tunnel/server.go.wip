package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/alphadose/haxmap"
	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
	connectip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate"
)

type TunnelServer struct {
	http3.Server

	// Maps tunnel destination address to CONNECT-IP connection.
	tuns haxmap.Map[netip.Addr, *connectip.Conn]
}

func NewTunnelServer(bind string, cfg *config.Config) (*TunnelServer, error) {
	server := &TunnelServer{
		Server: http3.Server{
			Addr:    bind,
			Handler: http.HandlerFunc(handleTunnel),
		},
		tuns: haxmap.New[netip.Addr, *connectip.Conn](),
	}

	return server, nil
}

func (t *TunnelServer) Start(ctx context.Context) error {
	return t.ListenAndServe()
}

func (t *TunnelServer) Stop(ctx context.Context) error {
	return t.Close()
}

func (t *TunnelServer) run(ctx context.Context) error {
	p := connectip.Proxy{}
	mux := http.NewServeMux()
	template := uritemplate.MustNew("https://proxy/connect")
	mux.HandleFunc("/connect/", func(w http.ResponseWriter, r *http.Request) {
		slog.Info("Received connection request", "remote", r.RemoteAddr)

		uuid := strings.TrimPrefix(r.URL.Path, "/connect/")
		if uuid == "" {
			slog.Error("Missing UUID in connection request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		slog.Info("Connection request for UUID", "uuid", uuid)

		req, err := connectip.ParseRequest(r, template)
		if err != nil {
			slog.Error("Failed to parse request", "error", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		conn, err := p.Proxy(w, req)
		if err != nil {
			slog.Error("Failed to proxy request", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer conn.Close()

		// Generate random IP from CGNAT range (100.64.0.0/10)
		// TODO(dsky): Manage via IPAM or generate from uuid.
		peerIP := netip.AddrFrom4([4]byte{
			100,
			64 + byte(mathrand.Intn(64)),
			byte(mathrand.Intn(256)),
			byte(mathrand.Intn(256)),
		})
		if err := conn.AssignAddresses(context.Background(), []netip.Prefix{
			netip.PrefixFrom(peerIP, 32),
		}); err != nil {
			slog.Error("Failed to assign address to connection", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}
		if err := conn.AdvertiseRoute(context.Background(), []connectip.IPRoute{
			{
				StartIP:    localAddr,
				EndIP:      localAddr,
				IPProtocol: 6, // TCP
			},
		}); err != nil {
			slog.Error("Failed to advertise route to connection", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		slog.Info("Peer IP assigned", "ip", peerIP)

		tunName, err := dev.Name()
		if err != nil {
			slog.Error("Failed to get TUN interface name", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		if err := addTUNPeer(tunName, peerIP); err != nil {
			slog.Error("Failed to add TUN peer", "error", err)
			w.WriteHeader(http.StatusInternalServerError)
			w.Write([]byte(err.Error()))
			return
		}

		t.tuns.Set(peerIP, conn)

		go func() {
			b := bufferPool.Get().([]byte)
			defer bufferPool.Put(b)

			// TODO: add support for writing batched packets.
			for {
				n, err := conn.ReadPacket(b)
				if err != nil {
					slog.Error("Failed to read from connection", "error", err)
					return
				}

				slog.Debug("Read from connection", "bytes", n)

				if _, err := dev.Write([][]byte{b[:n]}, 0); err != nil {
					slog.Error("Failed to write to TUN", "error", err)
					return
				}
			}
		}()

		select {
		case <-r.Context().Done():
			t.tuns.Del(peerIP)

			if err := removeTUNPeer(tunName, peerIP); err != nil {
				slog.Error("Failed to remove TUN peer", "error", err)
			}
		}
	})


}

func (t *tunnelNodeReconciler) run(ctx context.Context) error {
	var err error

	tunAddr := tunnel.NewApoxy4To6Prefix(t.cfg.CurrentProject, t.localTunnelNode.Name)
	if t.cfg.Tunnel != nil && t.cfg.Tunnel.Mode == configv1alpha1.TunnelModeUserspace {
		socksPort := uint16(1080)
		if t.cfg.Tunnel.SocksPort != nil {
			socksPort = uint16(*t.cfg.Tunnel.SocksPort)
		}

		t.tun, err = tunnel.CreateUserspaceTunnel(ctx, tunAddr.Addr(), t.bind, socksPort, t.cfg.Tunnel.PacketCapturePath, t.cfg.Verbose)
	} else {
		t.tun, err = tunnel.CreateKernelTunnel(tunAddr, t.bind, t.cfg.Verbose)
	}
	if err != nil {
		return fmt.Errorf("unable to create tunnel: %w", err)
	}
	defer t.tun.Close()

	slog.Debug("Running TunnelNode controller",
		slog.String("name", t.localTunnelNode.Name), slog.String("publicKey", t.tun.PublicKey()),
		slog.String("internalAddress", t.tun.InternalAddress().String()))

	client, err := config.DefaultAPIClient()
	if err != nil {
		return fmt.Errorf("unable to create API client: %w", err)
	}

	t.localTunnelNode.Status.Phase = corev1alpha.NodePhaseReady
	t.localTunnelNode.Status.PublicKey = t.tun.PublicKey()
	t.localTunnelNode.Status.InternalAddress = t.tun.InternalAddress().String()

	// Create/update the TunnelNode object in the API.
	slog.Debug("Creating/updating TunnelNode", slog.String("name", t.localTunnelNode.Name))

	if err := t.upsertTunnelNode(ctx, client, 10*time.Second); err != nil {
		log.Errorf("Failed to create/update TunnelNode: %v", err)
		return err
	}

	log.Infof("Starting tunnel node controller")

	mgr, err := ctrl.NewManager(client.RESTConfig, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set up overall controller manager: %w", err)
	}

	t.Client = mgr.GetClient()
	if err := t.setupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("unable to set up controller: %w", err)
	}
	tunnelOfferCtrl := &tunnelPeerOfferReconciler{
		Client:              mgr.GetClient(),
		localTunnelNodeName: t.localTunnelNode.Name,
		bind:                t.bind,
		peers:               make(map[string]*wireguard.IcePeer),
	}
	if err := tunnelOfferCtrl.setupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to set up controller: %w", err)
	}

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		if err := mgr.Start(ctx); err != nil {
			slog.Error("Manager exited non-zero", slog.Any("error", err))
		}
	}()

	// Set the initial status of the TunnelNode object.
	// Wait for the TunnelNode object to be deleted, or for the command to be cancelled.
	select {
	case <-doneCh:
	case <-ctx.Done():
	}

	return nil
}
