//go:build linux
// +build linux

package tunnel_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy-cli/pkg/firewall"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"github.com/apoxy-dev/apoxy-cli/pkg/stunserver"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
	"github.com/avast/retry-go/v4"
	"github.com/pion/ice/v4"
	icelogging "github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/stretchr/testify/require"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netns"
	"golang.org/x/sync/errgroup"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

var (
	localAreaNetwork      = netip.MustParsePrefix("192.168.0.0/24")
	virtualPrivateNetwork = netip.MustParsePrefix("192.168.1.0/24")
	dmzNetwork            = netip.MustParsePrefix("192.168.2.0/24")
	turnAddress           = utils.FirstValidAddress(dmzNetwork)
)

func TestICETunnel(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	// Check if we have the NET_ADMIN capability.
	netAdmin, err := hasCapability(CAP_NET_ADMIN)
	require.NoError(t, err)
	if !netAdmin {
		t.Skip("requires NET_ADMIN capability")
	}

	require.NoError(t, firewall.EnableIPForwarding())

	// Backup the original network namespace.
	origns, err := netns.Get()
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, origns.Close())
	})

	// Create a dummy interface for our STUN/TURN server.
	dummy, err := createDummyInterface(dmzNetwork)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = netlink.LinkDel(dummy)
	})

	// Flush the NAT table.
	require.NoError(t, firewall.FlushNAT(origns))

	namespaceHandles := make(chan namespaceAndNetwork)
	t.Cleanup(func() {
		close(namespaceHandles)
	})

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		return stunserver.ListenAndServe(ctx, net.JoinHostPort(turnAddress.String(), "3478"))
	})

	g.Go(func() error {
		// Lock the OS Thread so we don't accidentally switch namespaces
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		if err := netns.Set(origns); err != nil {
			return fmt.Errorf("failed to set original network namespace: %w", err)
		}

		var i int
		for i < 2 {
			t.Logf("Waiting for network namespace %d", i)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case ns, ok := <-namespaceHandles:
				if !ok {
					return errors.New("namespace channel closed")
				}

				t.Logf("Setting up veth pair for network namespace %d", i)

				// Create a new veth pair and move one end to the new network namespace.
				err := netlink.LinkAdd(&netlink.Veth{
					LinkAttrs: netlink.LinkAttrs{
						Name: fmt.Sprintf("apoxy%d", i),
					},
					PeerName:      "apoxy0",
					PeerNamespace: netlink.NsFd(int(ns.handle)),
				})
				if err != nil {
					return fmt.Errorf("failed to create veth pair: %w", err)
				}

				link, err := netlink.LinkByName(fmt.Sprintf("apoxy%d", i))
				if err != nil {
					return fmt.Errorf("failed to find veth interface: %w", err)
				}

				// Bring up the host side of the veth pair.
				if err := netlink.LinkSetUp(link); err != nil {
					return fmt.Errorf("failed to enable veth interface: %w", err)
				}

				// Set the address of the host side veth interface.
				err = netlink.AddrAdd(link, &netlink.Addr{
					IPNet: &net.IPNet{
						IP:   utils.FirstValidAddress(ns.network).AsSlice(),
						Mask: net.CIDRMask(ns.network.Bits(), len(ns.network.Addr().AsSlice())*8),
					},
					Label: fmt.Sprintf("apoxy%d", i),
				})
				if err != nil {
					return fmt.Errorf("failed to assign IP address to veth interface: %w", err)
				}

				// Remove the veth pair when we're done.
				t.Cleanup(func() {
					_ = netlink.LinkDel(link)
				})

				t.Logf("configuring nat for network namespace %d", i)

				// Forward traffic from the network namespace to the bridge device using NAT.
				if err := firewall.EnableNAT(origns, fmt.Sprintf("apoxy%d", i), "apoxybr0"); err != nil {
					return fmt.Errorf("failed to setup NAT rules: %w", err)
				}
			}

			i++
		}

		t.Log("network namespaces setup done")

		return nil
	})

	iceConf := &ice.AgentConfig{
		Urls: []*stun.URI{
			{
				Scheme:   stun.SchemeTypeTURN,
				Host:     turnAddress.String(),
				Port:     3478,
				Proto:    stun.ProtoTypeTCP,
				Username: "apoxy",
				Password: "apoxy",
			},
		},
		NetworkTypes:  []ice.NetworkType{ice.NetworkTypeUDP4},
		CheckInterval: ptr.To(50 * time.Millisecond),
		CandidateTypes: []ice.CandidateType{
			ice.CandidateTypeHost,
			ice.CandidateTypeServerReflexive,
			ice.CandidateTypePeerReflexive,
			ice.CandidateTypeRelay,
		},
		LoggerFactory: &icelogging.DefaultLoggerFactory{
			Writer: log.NewDefaultLogWriter(log.InfoLevel),
		},
	}

	offerFromController := make(chan *corev1alpha.ICEOffer, 1)
	offerFromControlled := make(chan *corev1alpha.ICEOffer, 1)
	t.Cleanup(func() {
		close(offerFromController)
		close(offerFromControlled)
	})

	var haveOffersFromBothSides sync.WaitGroup
	haveOffersFromBothSides.Add(2)

	var controllerPeerConfigMu, controlledPeerConfigMu sync.Mutex
	var controllerPeerConfig, controlledPeerConfig *wireguard.PeerConfig

	// Controlling peer.
	g.Go(func() error {
		// Lock the OS Thread so we don't accidentally switch namespaces
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		t.Logf("Setting up network namespace 1")

		newns, err := setupNetworkNamespace(ctx, namespaceHandles, localAreaNetwork, utils.FirstValidAddress(localAreaNetwork).Next())
		if err != nil {
			return fmt.Errorf("failed to setup network namespace: %w", err)
		}
		defer newns.Close()

		t.Log("network namespace 1 setup")

		bind := wireguard.NewIceBind(ctx, iceConf)
		t.Cleanup(func() {
			if err := bind.Close(); err != nil {
				t.Logf("error closing bind: %v", err)
			}
		})

		t.Logf("Creating userspace tunnel")

		privateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("could not generate private key: %w", err)
		}

		addr := utils.FirstValidAddress(virtualPrivateNetwork)
		wgNet, err := wireguard.Network(&wireguard.DeviceConfig{
			PrivateKey: ptr.To(privateKey.String()),
			Address:    []string{addr.String()},
			Bind:       bind,
		})
		if err != nil {
			return fmt.Errorf("could not create WireGuard network: %w", err)
		}
		defer wgNet.Close()

		t.Log("writing peer config")

		controllerPeerConfigMu.Lock()
		controllerPeerConfig = &wireguard.PeerConfig{
			PublicKey:  ptr.To(wgNet.PublicKey()),
			AllowedIPs: []string{addr.String() + "/32"},
			Endpoint:   ptr.To("controller"),
		}
		controllerPeerConfigMu.Unlock()

		// Time for coturn to start and become available.
		time.Sleep(time.Second)

		icePeer, err := bind.NewPeer(true)
		if err != nil {
			return fmt.Errorf("failed to create peer: %w", err)
		}
		t.Cleanup(func() {
			require.NoError(t, icePeer.Close())
		})

		t.Logf("initializing controller peer")

		icePeer.OnCandidate = func(c string) {
			t.Logf("controller candidate: %s", c)

			ufrag, pwd := icePeer.LocalUserCredentials()
			cs := icePeer.LocalCandidates()

			select {
			case <-ctx.Done():
				return
			case offerFromController <- &corev1alpha.ICEOffer{
				Ufrag:      ufrag,
				Password:   pwd,
				Candidates: cs,
			}:
				return
			}
		}

		if err := icePeer.Init(); err != nil {
			return fmt.Errorf("failed to init peer: %w", err)
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		g.Go(func() error {
			firstOffer := true
			for {
				select {
				case <-ctx.Done():
					return nil
				case remoteOffer, ok := <-offerFromControlled:
					if !ok {
						return errors.New("controlled peer closed")
					}

					t.Log("got remote offer from controlled peer")

					if err := icePeer.AddRemoteOffer(remoteOffer); err != nil {
						return fmt.Errorf("failed to add remote offer: %w", err)
					}

					if firstOffer {
						haveOffersFromBothSides.Done()
						firstOffer = false
					}
				}
			}
		})

		t.Log("waiting for offers from both sides")

		haveOffersFromBothSides.Wait()

		err = retry.Do(func() error {
			t.Log("connecting to controlled peer")

			if err := icePeer.Connect(ctx, "controlled"); err != nil {
				return fmt.Errorf("failed to connect to controlled peer: %w", err)
			}

			return nil
		}, retry.Context(ctx), retry.Attempts(5), retry.Delay(time.Second))
		if err != nil {
			return fmt.Errorf("failed to connect to controlled peer: %w", err)
		}

		t.Log("connected to controlled peer")

		var remotePeerConfig *wireguard.PeerConfig
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}

			controlledPeerConfigMu.Lock()
			remotePeerConfig = controlledPeerConfig
			controlledPeerConfigMu.Unlock()
			if remotePeerConfig != nil {
				break
			}
		}

		if err := wgNet.AddPeer(remotePeerConfig); err != nil {
			return fmt.Errorf("failed to add peer: %w", err)
		}

		t.Log("Making http request to controlled peer")

		client := &http.Client{
			Transport: &http.Transport{
				DialContext: wgNet.DialContext,
			},
			Timeout: 5 * time.Second,
		}

		controlledPeerAddress := utils.FirstValidAddress(virtualPrivateNetwork).Next()
		resp, err := client.Get("http://" + net.JoinHostPort(controlledPeerAddress.String(), "8080"))
		if err != nil {
			return fmt.Errorf("failed to make http request: %w", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("unexpected status code: %d", resp.StatusCode)
		}

		respBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %w", err)
		}

		t.Logf("response: %s", string(respBytes))

		return context.Canceled
	})

	// Controlled peer.
	g.Go(func() error {
		// Lock the OS Thread so we don't accidentally switch namespaces
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		t.Logf("Setting up network namespace 2")

		newns, err := setupNetworkNamespace(ctx, namespaceHandles, localAreaNetwork, utils.FirstValidAddress(localAreaNetwork).Next())
		if err != nil {
			return fmt.Errorf("failed to setup network namespace: %w", err)
		}
		defer newns.Close()

		t.Log("network namespace 2 setup")

		bind := wireguard.NewIceBind(ctx, iceConf)
		t.Cleanup(func() {
			if err := bind.Close(); err != nil {
				t.Logf("error closing bind: %v", err)
			}
		})

		privateKey, err := wgtypes.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("could not generate private key: %w", err)
		}

		addr := utils.FirstValidAddress(virtualPrivateNetwork).Next()
		wgNet, err := wireguard.Network(&wireguard.DeviceConfig{
			PrivateKey: ptr.To(privateKey.String()),
			Address:    []string{addr.String()},
			Bind:       bind,
		})
		if err != nil {
			return fmt.Errorf("could not create WireGuard network: %w", err)
		}
		defer wgNet.Close()

		t.Log("writing peer config")

		controlledPeerConfigMu.Lock()
		controlledPeerConfig = &wireguard.PeerConfig{
			PublicKey:  ptr.To(wgNet.PublicKey()),
			AllowedIPs: []string{addr.String() + "/32"},
			Endpoint:   ptr.To("controlled"),
		}
		controlledPeerConfigMu.Unlock()

		// Time for coturn to start and become available.
		time.Sleep(time.Second)

		icePeer, err := bind.NewPeer(false)
		if err != nil {
			return fmt.Errorf("failed to create peer: %w", err)
		}
		t.Cleanup(func() {
			require.NoError(t, icePeer.Close())
		})

		t.Log("initializing controlled peer")

		icePeer.OnCandidate = func(c string) {
			t.Logf("controlled candidate: %s", c)

			ufrag, pwd := icePeer.LocalUserCredentials()
			cs := icePeer.LocalCandidates()

			select {
			case <-ctx.Done():
				return
			case offerFromControlled <- &corev1alpha.ICEOffer{
				Ufrag:      ufrag,
				Password:   pwd,
				Candidates: cs,
			}:
				return
			}
		}

		if err := icePeer.Init(); err != nil {
			return fmt.Errorf("failed to init peer: %w", err)
		}

		ctx, cancel := context.WithCancel(ctx)
		defer cancel()

		g.Go(func() error {
			firstOffer := true
			for {
				select {
				case <-ctx.Done():
					return nil
				case remoteOffer, ok := <-offerFromController:
					if !ok {
						return errors.New("controller peer closed")
					}

					t.Log("got remote offer from controller peer")

					if err := icePeer.AddRemoteOffer(remoteOffer); err != nil {
						return fmt.Errorf("failed to add remote offer: %w", err)
					}

					if firstOffer {
						haveOffersFromBothSides.Done()
						firstOffer = false
					}
				}
			}
		})

		t.Log("waiting for offers from both sides")

		haveOffersFromBothSides.Wait()

		err = retry.Do(func() error {
			t.Log("connecting to controller peer")

			if err := icePeer.Connect(ctx, "controller"); err != nil {
				t.Logf("failed to connect to controller peer: %v", err)
				return fmt.Errorf("failed to connect to controller peer: %w", err)
			}

			return nil
		}, retry.Context(ctx), retry.Attempts(5), retry.Delay(time.Second))
		if err != nil {
			return fmt.Errorf("failed to connect to controller peer: %w", err)
		}

		var remotePeerConfig *wireguard.PeerConfig
		for {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(100 * time.Millisecond):
			}

			controllerPeerConfigMu.Lock()
			remotePeerConfig = controllerPeerConfig
			controllerPeerConfigMu.Unlock()
			if remotePeerConfig != nil {
				break
			}
		}

		if err := wgNet.AddPeer(remotePeerConfig); err != nil {
			return fmt.Errorf("failed to add peer: %w", err)
		}

		t.Log("Starting http server")

		mux := http.NewServeMux()

		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("Hello, World!"))
		})

		srv := &http.Server{
			Addr:    net.JoinHostPort(addr.String(), "8080"),
			Handler: mux,
		}
		defer srv.Close()

		go func() {
			<-ctx.Done()

			if err := srv.Close(); err != nil {
				t.Logf("error closing http server: %v", err)
			}
		}()

		// Listen on the WireGuard network.
		lis, err := wgNet.Listen("tcp", srv.Addr)
		if err != nil {
			return fmt.Errorf("failed to listen: %w", err)
		}

		t.Log("serving http")

		if err := srv.Serve(lis); err != nil && !errors.Is(err, http.ErrServerClosed) {
			t.Logf("could not serve http: %v", err)
		}

		t.Log("controlled peer completed")

		return nil
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		require.NoError(t, err)
	}
}

// Create a dummy interface and assign an IP address to it.
func createDummyInterface(network netip.Prefix) (netlink.Link, error) {
	link, err := netlink.LinkByName("apoxyturn0")
	if err == nil {
		_ = netlink.LinkDel(link) // If exists, delete existing link
	}

	// Create a new dummy interface
	err = netlink.LinkAdd(&netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: "apoxyturn0",
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create dummy interface: %w", err)
	}

	link, err = netlink.LinkByName("apoxyturn0")
	if err != nil {
		return nil, fmt.Errorf("failed to find dummy interface: %w", err)
	}

	// Bring the dummy interface up
	if err := netlink.LinkSetUp(link); err != nil {
		_ = netlink.LinkDel(link)
		return nil, fmt.Errorf("failed to enable dummy interface: %w", err)
	}

	// Assign IP address to the dummy interface
	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   utils.FirstValidAddress(network).AsSlice(),
			Mask: net.CIDRMask(network.Bits(), len(network.Addr().AsSlice())*8),
		},
	})
	if err != nil {
		_ = netlink.LinkDel(link)
		return nil, fmt.Errorf("failed to assign IP address to dummy interface: %w", err)
	}

	return link, nil
}

type namespaceAndNetwork struct {
	handle  netns.NsHandle
	network netip.Prefix
}

func setupNetworkNamespace(ctx context.Context, namespaceHandles chan namespaceAndNetwork, network netip.Prefix, addr netip.Addr) (netns.NsHandle, error) {
	// Create a new network namespace for this thread.
	newns, err := netns.New()
	if err != nil {
		return netns.None(), fmt.Errorf("failed to create new network namespace: %w", err)
	}

	namespaceHandles <- namespaceAndNetwork{
		handle:  newns,
		network: network,
	}

	var link netlink.Link
	for link == nil {
		select {
		case <-ctx.Done():
			return newns, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		default:
		}

		link, err = netlink.LinkByName("apoxy0")
		if err != nil {
			if _, ok := err.(netlink.LinkNotFoundError); !ok {
				return newns, fmt.Errorf("failed to find veth interface: %w", err)
			}
		}
	}

	// Enable the veth interface.
	if err := netlink.LinkSetUp(link); err != nil {
		_ = newns.Close()
		return newns, fmt.Errorf("failed to enable veth interface: %w", err)
	}

	err = netlink.AddrAdd(link, &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   addr.AsSlice(),
			Mask: net.CIDRMask(network.Bits(), len(network.Addr().AsSlice())*8),
		},
		Label: "apoxy0",
	})
	if err != nil {
		_ = newns.Close()
		return newns, fmt.Errorf("failed to assign IP address to veth interface: %w", err)
	}

	// Add a default route via the host side of the veth pair.
	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst: &net.IPNet{
			IP:   netip.MustParseAddr("0.0.0.0").AsSlice(),
			Mask: net.CIDRMask(0, 32),
		},
		Gw: utils.FirstValidAddress(network).AsSlice(),
	})
	if err != nil {
		_ = newns.Close()
		return newns, fmt.Errorf("failed to add default route: %w", err)
	}

	return newns, nil
}
