package wireguard_test

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
	"k8s.io/utils/ptr"

	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
)

func TestWireGuardNetwork(t *testing.T) {
	// slog.SetLogLoggerLevel(slog.LevelDebug)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("Hello, World!"))
		if err != nil {
			t.Fatalf("could not write response: %v", err)
		}
	})

	// Create a new test http server listening on a random local port
	httpServer := httptest.NewServer(handler)
	t.Cleanup(httpServer.Close)

	serverPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	serverPublicKey := serverPrivateKey.PublicKey()

	serverPort, err := pickUnusedUDP4Port()
	require.NoError(t, err)

	clientPrivateKey, err := wgtypes.GeneratePrivateKey()
	require.NoError(t, err)

	clientPublicKey := clientPrivateKey.PublicKey()

	clientPort, err := pickUnusedUDP4Port()
	require.NoError(t, err)

	serverWGNet, err := wireguard.Network(&wireguard.DeviceConfig{
		PrivateKey: ptr.To(base64.StdEncoding.EncodeToString(serverPrivateKey[:])),
		ListenPort: ptr.To(serverPort),
		Address:    []string{"10.0.0.1/32"},
	})
	require.NoError(t, err)
	t.Cleanup(serverWGNet.Close)

	err = serverWGNet.AddPeer(&wireguard.PeerConfig{
		PublicKey:  ptr.To(base64.StdEncoding.EncodeToString(clientPublicKey[:])),
		Endpoint:   ptr.To(net.JoinHostPort("localhost", strconv.Itoa(int(clientPort)))),
		AllowedIPs: []string{"10.0.0.2/32"},
	})
	require.NoError(t, err)

	require.NoError(t, serverWGNet.FowardToLoopback(context.Background()))

	clientWGNet, err := wireguard.Network(&wireguard.DeviceConfig{
		PrivateKey: ptr.To(base64.StdEncoding.EncodeToString(clientPrivateKey[:])),
		ListenPort: ptr.To(clientPort),
		Address:    []string{"10.0.0.2/32"},
	})
	require.NoError(t, err)
	t.Cleanup(clientWGNet.Close)

	err = clientWGNet.AddPeer(&wireguard.PeerConfig{
		PublicKey:  ptr.To(base64.StdEncoding.EncodeToString(serverPublicKey[:])),
		Endpoint:   ptr.To(net.JoinHostPort("localhost", strconv.Itoa(int(serverPort)))),
		AllowedIPs: []string{"10.0.0.1/32"},
	})
	require.NoError(t, err)

	// Create a http httpClient using the wgNet dialer
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: clientWGNet.DialContext,
		},
		Timeout: 100 * time.Millisecond,
	}

	t.Run("FowardToLoopback", func(t *testing.T) {
		// Make a request to the test server (through the wireguard network).
		resp, err := httpClient.Get("http://" + net.JoinHostPort("10.0.0.1",
			strconv.Itoa(httpServer.Listener.Addr().(*net.TCPAddr).Port)))
		require.NoError(t, err)
		t.Cleanup(func() {
			require.NoError(t, resp.Body.Close())
		})

		require.Equal(t, http.StatusOK, resp.StatusCode)

		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		require.Equal(t, "Hello, World!", string(body))
	})

	t.Run("RemovePeer", func(t *testing.T) {
		// Remove the client peer from the server network
		require.NoError(t, serverWGNet.RemovePeer(clientWGNet.PublicKey()))

		// Make a request to the test server (through the wireguard network).
		// This request should fail because the client peer has been removed from the server network.
		_, err = httpClient.Get("http://" + net.JoinHostPort("10.0.0.1",
			strconv.Itoa(httpServer.Listener.Addr().(*net.TCPAddr).Port)))
		require.ErrorIs(t, err, context.DeadlineExceeded)
	})
}

func pickUnusedUDP4Port() (uint16, error) {
	for i := 0; i < 10; i++ {
		addr, err := net.ResolveUDPAddr("udp4", "localhost:0")
		if err != nil {
			return 0, err
		}
		l, err := net.ListenUDP("udp4", addr)
		if err != nil {
			return 0, err
		}
		defer l.Close()
		return uint16(l.LocalAddr().(*net.UDPAddr).Port), nil
	}

	return 0, errors.New("could not find unused UDP port")
}
