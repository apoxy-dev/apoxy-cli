//go:build linux

package tunnel_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel"
	tunnelnet "github.com/apoxy-dev/apoxy-cli/pkg/tunnel/net"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/router"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/token"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
)

func TestTunnelEndToEnd(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	netAdmin, err := utils.IsNetAdmin()
	require.NoError(t, err)

	if !netAdmin {
		t.Skip("requires NET_ADMIN capability")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)

	certsDir := t.TempDir()

	// Save the server certificate and private key to the temporary directory as PEM files
	err = cryptoutils.SaveCertificatePEM(serverCert, certsDir, "server", false)
	require.NoError(t, err)

	// Create a client UUID and JWT token
	// This UUID is used to identify the client in the server's tunnel node list.
	// The JWT token is used for authentication and contains the client's UUID as the subject.
	clientUUID := uuid.New()

	jwtPrivateKeyPEM, jwtPublicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	jwtPrivateKey, err := cryptoutils.ParseEllipticPrivateKeyPEM(jwtPrivateKeyPEM)
	require.NoError(t, err)

	clientAuthToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": clientUUID.String(),
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	}).SignedString(jwtPrivateKey)
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha.Install(scheme))

	clientTunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "client",
			UID:  apimachinerytypes.UID(clientUUID.String()),
		},
		Status: corev1alpha.TunnelNodeStatus{
			Credentials: &corev1alpha.TunnelNodeCredentials{
				Token: clientAuthToken,
			},
		},
	}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(clientTunnelNode).WithStatusSubresource(clientTunnelNode).Build()

	jwtValidator, err := token.NewInMemoryValidator(jwtPublicKeyPEM)
	require.NoError(t, err)

	lr, err := tunnelnet.LocalRouteIPv6()
	require.NoError(t, err)

	fmt.Println("Local route:", lr)

	// Create a mock router for testing
	mockRouter := router.NewMockRouter()

	server := tunnel.NewTunnelServer(
		kubeClient,
		jwtValidator,
		mockRouter,
		tunnel.WithLocalRoute(lr),
		tunnel.WithCertPath(filepath.Join(certsDir, "server.crt")),
		tunnel.WithKeyPath(filepath.Join(certsDir, "server.key")),
	)

	// Register the client with the server
	server.AddTunnelNode(clientTunnelNode)

	// Create a new tunnel client
	client, err := tunnel.NewTunnelClient(
		tunnel.WithUUID(clientUUID),
		tunnel.WithAuthToken(clientAuthToken),
		tunnel.WithRootCAs(cryptoutils.CertPoolForCertificate(caCert)),
		tunnel.WithPcapPath("client.pcap"),
	)
	require.NoError(t, err)

	g, ctx := errgroup.WithContext(ctx)

	// Start a little http server listening on localhost (to test the tunnel)
	httpListener, err := net.Listen("tcp", "localhost:0")
	require.NoError(t, err)

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintln(w, "Hello, world!")
		}),
	}

	g.Go(func() error {
		defer t.Log("HTTP test server closed")

		t.Log("Starting HTTP test server")

		if err := httpServer.Serve(httpListener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("unable to start HTTP server: %v", err)
		}

		return nil
	})

	// Start the server
	g.Go(func() error {
		defer t.Log("Tunnel server closed")

		t.Log("Starting tunnel server")

		if err := server.Start(ctx); err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("unable to start server: %v", err)
		}

		return nil
	})

	// Start the client
	g.Go(func() error {
		// Stop the server and http test server when the client is done
		defer func() {
			_ = server.Stop()
			_ = httpServer.Close()
		}()

		// Wait for the server to start
		time.Sleep(1 * time.Second)

		if err := client.Start(ctx); err != nil {
			return fmt.Errorf("unable to connect to server: %v", err)
		}
		defer func() {
			_ = client.Stop()
		}()

		clientAddresses, err := client.LocalAddresses()
		if err != nil {
			return fmt.Errorf("unable to get local addresses: %v", err)
		}

		t.Logf("Assigned client addresses: %v", clientAddresses)

		// TODO (dpeckett): Make a request to the test http server
		// This will fail atm due the servers TUN device not being assigned a
		// valid IP address.

		t.Log("Attempting connection")

		httpPort := httpListener.Addr().(*net.TCPAddr).Port

		resp, err := http.Get("http://" + net.JoinHostPort(clientAddresses[0].Addr().String(), fmt.Sprintf("%d", httpPort)))
		require.NoError(t, err)
		defer resp.Body.Close()

		// Read the response body
		body, err := io.ReadAll(resp.Body)
		require.NoError(t, err)

		assert.Equal(t, http.StatusOK, resp.StatusCode)
		assert.Equal(t, "Hello, world!\n", string(body))

		t.Log("Connection successful")

		return nil
	})

	require.NoError(t, g.Wait())
}
