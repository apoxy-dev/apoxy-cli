//go:build linux
// +build linux

package wireguard_test

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
)

func TestKernelModeTransport(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	// Check if we have the NET_ADMIN capability.
	netAdmin, err := utils.CanCreateTUNInterfaces()
	require.NoError(t, err)
	if !netAdmin {
		t.Skip("requires NET_ADMIN capability")
	}

	// Create a new kernel tunnel.
	kernelPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	projectID := uuid.New()
	wgAddress := tunnel.NewApoxy4To6Prefix(projectID, "kernel-node")
	kernelWGNet, err := wireguard.NewKernelModeTransport(&wireguard.DeviceConfig{
		PrivateKey: ptr.To(kernelPrivateKey.String()),
		Address:    []string{wgAddress.String()},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, kernelWGNet.Close())
	})

	// Create a new userspace wireguard network.
	privateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	listenPort, err := utils.UnusedUDP4Port()
	require.NoError(t, err)

	wgAddress = tunnel.NewApoxy4To6Prefix(projectID, "userspace-node")

	wgNet, err := wireguard.NewUserspaceTransport(&wireguard.DeviceConfig{
		PrivateKey: ptr.To(privateKey.String()),
		ListenPort: ptr.To(listenPort),
		Address:    []string{wgAddress.String()},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, wgNet.Close())
	})

	// Add a peer to the tunnel.
	err = kernelWGNet.AddPeer(&wireguard.PeerConfig{
		PublicKey:  ptr.To(privateKey.PublicKey().String()),
		AllowedIPs: []string{wgAddress.String()},
		Endpoint:   ptr.To(net.JoinHostPort("localhost", strconv.Itoa(int(listenPort)))),
	})
	require.NoError(t, err)

	// Retrieve the listen port of the tunnel (if it has one).
	listenPort, err = kernelWGNet.ListenPort()
	require.NoError(t, err)

	// Add a peer to the wireguard network.
	kernelWGAddrs, err := kernelWGNet.LocalAddresses()
	require.NoError(t, err)
	require.NotEmpty(t, kernelWGAddrs)

	err = wgNet.AddPeer(&wireguard.PeerConfig{
		PublicKey:  ptr.To(kernelWGNet.PublicKey()),
		AllowedIPs: []string{kernelWGAddrs[0].String()},
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
	firstAddr := kernelWGAddrs[0].Addr()

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

	knownPeers, err := kernelWGNet.Peers()
	require.NoError(t, err)

	require.Len(t, knownPeers, 1)
	require.Equal(t, *knownPeers[0].PublicKey, privateKey.PublicKey().String())
}
