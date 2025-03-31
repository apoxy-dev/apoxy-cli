//go:build linux
// +build linux

package tunnel_test

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
)

func TestKernelTunnel(t *testing.T) {
	//	slog.SetLogLoggerLevel(slog.LevelDebug)

	// Check if we have the NET_ADMIN capability.
	netAdmin, err := hasNetAdminCapability()
	require.NoError(t, err)
	if !netAdmin {
		t.Skip("requires NET_ADMIN capability")
	}

	// Create a new kernel tunnel.
	projectID := uuid.New()
	wgAddress := tunnel.NewApoxy4To6Prefix(projectID, "kernel-node")
	tun, err := tunnel.CreateKernelTunnel(wgAddress)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, tun.Close())
	})

	// Create a new userspace wireguard network.
	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	listenPort, err := utils.UnusedUDP4Port()
	require.NoError(t, err)

	wgAddress = tunnel.NewApoxy4To6Prefix(projectID, "userspace-node")

	wgNet, err := wireguard.Network(&wireguard.DeviceConfig{
		PrivateKey: ptr.To(privateKey.String()),
		ListenPort: ptr.To(listenPort),
		Address:    []string{wgAddress.String()},
	})
	require.NoError(t, err)
	t.Cleanup(wgNet.Close)

	// Add a peer to the tunnel.
	err = tun.AddPeer(&wireguard.PeerConfig{
		PublicKey:  ptr.To(privateKey.PublicKey().String()),
		AllowedIPs: []string{wgAddress.String()},
		Endpoint:   ptr.To(net.JoinHostPort("localhost", strconv.Itoa(int(listenPort)))),
	})
	require.NoError(t, err)

	// Retrieve the listen port of the tunnel (if it has one).
	listenPort, err = tun.ListenPort()
	require.NoError(t, err)

	// Add a peer to the wireguard network.
	err = wgNet.AddPeer(&wireguard.PeerConfig{
		PublicKey:  ptr.To(tun.PublicKey()),
		AllowedIPs: []string{tun.InternalAddress().String()},
		Endpoint:   ptr.To(net.JoinHostPort("localhost", strconv.Itoa(int(listenPort)))),
	})
	require.NoError(t, err)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Hello, World!"))
		if err != nil {
			t.Fatalf("could not write response: %v", err)
		}
	})

	// Get the first ip of the tun internal CIDR
	firstAddr := netip.MustParsePrefix(tun.InternalAddress().String()).Addr()

	// Start an HTTP server listening on the tunnel interface.
	srv := &http.Server{
		Addr:    net.JoinHostPort(firstAddr.String(), "8080"),
		Handler: handler,
	}
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})

	lis, err := net.Listen("tcp", srv.Addr)
	require.NoError(t, err)

	go func() {
		if err := srv.Serve(lis); err != nil && err != http.ErrServerClosed {
			t.Logf("could not serve http: %v", err)
		}
	}()

	// Make a request to the server using the wireguard network.
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: wgNet.DialContext,
		},
		Timeout: 5 * time.Second,
	}

	t.Logf("Making request to http://%s", srv.Addr)

	resp, err := httpClient.Get("http://" + srv.Addr)
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, "Hello, World!", string(body))

	knownPeers, err := tun.Peers()
	require.NoError(t, err)

	require.Len(t, knownPeers, 1)
	require.Equal(t, *knownPeers[0].PublicKey, privateKey.PublicKey().String())
}

func hasNetAdminCapability() (bool, error) {
	// Check if we are running as root
	if unix.Geteuid() == 0 {
		return true, nil
	}

	// Get the current process's capabilities
	var capData unix.CapUserData
	var capHeader unix.CapUserHeader

	// Set the version to the latest version
	capHeader.Version = unix.LINUX_CAPABILITY_VERSION_3

	// Get capabilities
	err := unix.Capget(&capHeader, &capData)
	if err != nil {
		return false, fmt.Errorf("failed to get capabilities: %v", err)
	}

	// Check if the NET_ADMIN capability is present
	const CAP_NET_ADMIN = 12
	netAdminMask := uint32(1) << (CAP_NET_ADMIN % 32)
	if capData.Effective&(netAdminMask) != 0 {
		return true, nil
	}

	return false, nil
}
