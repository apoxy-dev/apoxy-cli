package alpha

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	proxyclient "golang.org/x/net/proxy"
	"golang.org/x/sync/errgroup"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"

	configv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/client/versioned/fake"
)

func TestRunTunnel(t *testing.T) {
	slog.SetLogLoggerLevel(slog.LevelDebug)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	projectID := uuid.New()

	client := fake.NewSimpleClientset()

	g, egCtx := errgroup.WithContext(ctx)

	// Create a new test http server listening on a random local port
	var httpServerPort int
	g.Go(func() error {
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, err := w.Write([]byte("Hello, World!"))
			if err != nil {
				t.Fatalf("could not write response: %v", err)
			}
		})

		httpServer := httptest.NewServer(handler)
		httpServerPort = httpServer.Listener.Addr().(*net.TCPAddr).Port

		<-egCtx.Done()

		httpServer.Close()

		return nil
	})

	// Run a STUN server to handle STUN requests locally.
	g.Go(func() error {
		return listenForSTUNRequests(egCtx, "localhost:3478")
	})

	// Run two tunnel nodes
	g.Go(func() error {
		cfg := &configv1alpha1.Config{
			CurrentProject: projectID,
			Tunnel: &configv1alpha1.TunnelConfig{
				Mode:        configv1alpha1.TunnelModeUserspace,
				SocksPort:   ptr.To(1080),
				STUNServers: []string{"localhost:3478"},
			},
		}

		return runTunnel(egCtx, cfg, client, "testdata/tunnelnode1.yaml", "")
	})

	g.Go(func() error {
		cfg := &configv1alpha1.Config{
			CurrentProject: projectID,
			Tunnel: &configv1alpha1.TunnelConfig{
				Mode:        configv1alpha1.TunnelModeUserspace,
				SocksPort:   ptr.To(1081),
				STUNServers: []string{"localhost:3478"},
			},
		}

		return runTunnel(egCtx, cfg, client, "testdata/tunnelnode2.yaml", "")
	})

	go func() {
		if err := g.Wait(); err != nil {
			slog.Error("Error running tunnel", slog.Any("error", err))
			os.Exit(1)
		}
	}()

	t.Logf("Waiting for tunnel nodes to be ready")

	require.NoError(t, pollUntilReady(ctx, client, "tunnelnode1"))
	require.NoError(t, pollUntilReady(ctx, client, "tunnelnode2"))

	t.Logf("Tunnel 1 and 2 are ready")

	// Connect via the SOCKS proxy of tunnelnode1 to the test server listening on tunnelnode2
	tunnelNode2, err := client.CoreV1alpha().TunnelNodes().Get(ctx, "tunnelnode2", metav1.GetOptions{})
	require.NoError(t, err)

	dialer, err := proxyclient.SOCKS5("tcp", "localhost:1080", nil, proxyclient.Direct)
	require.NoError(t, err)

	httpClient := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
	}

	tunnelNode2AddrPrefix, err := netip.ParsePrefix(tunnelNode2.Status.InternalAddress)
	require.NoError(t, err)

	resp, err := httpClient.Get("http://" + net.JoinHostPort(tunnelNode2AddrPrefix.Addr().String(), strconv.Itoa(httpServerPort)))
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	require.Equal(t, http.StatusOK, resp.StatusCode)
}

func pollUntilReady(ctx context.Context, client versioned.Interface, name string) error {
	for {
		tunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, name, metav1.GetOptions{})
		if err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("error getting tunnelnode: %w", err)
		}

		if tunnelNode != nil && tunnelNode.Status.PublicKey != "" && tunnelNode.Status.ExternalAddress != "" {
			break
		}

		time.Sleep(time.Second)
	}

	return nil
}
