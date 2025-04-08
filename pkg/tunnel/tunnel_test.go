//go:build linux

package tunnel_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	apimachinerytypes "k8s.io/apimachinery/pkg/types"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestTunnelEndToEnd(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	// Check if we have the NET_ADMIN capability.
	netAdmin, err := utils.CanCreateTUNInterfaces()
	require.NoError(t, err)
	if !netAdmin {
		t.Skip("requires NET_ADMIN capability")
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	serverCert, rootCAs, err := utils.GenerateSelfSignedTLSCert()
	require.NoError(t, err)

	certsDir := t.TempDir()

	// Save the server certificate and private key to the temporary directory as PEM files
	err = utils.SaveTLSCertificatePEM(serverCert, certsDir)
	require.NoError(t, err)

	// Create a client UUID and JWT token
	// This UUID is used to identify the client in the server's tunnel node list.
	// The JWT token is used for authentication and contains the client's UUID as the subject.
	clientUUID := uuid.New().String()

	jwtPrivateKey, jwtPublicKey := generateKeyPair(t)

	clientAuthToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"sub": clientUUID,
		"iat": time.Now().Unix(),
		"exp": time.Now().Add(time.Minute * 5).Unix(),
	}).SignedString(jwtPrivateKey)
	require.NoError(t, err)

	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha.Install(scheme))

	clientTunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "client",
			UID:  apimachinerytypes.UID(clientUUID),
		},
		Status: corev1alpha.TunnelNodeStatus{
			Credentials: string(jwtPublicKey),
		},
	}

	kubeClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(clientTunnelNode).WithStatusSubresource(clientTunnelNode).Build()

	server := tunnel.NewTunnelServer(tunnel.WithCertPath(filepath.Join(certsDir, "cert.pem")),
		tunnel.WithKeyPath(filepath.Join(certsDir, "key.pem")),
		tunnel.WithClient(kubeClient))
	t.Cleanup(func() {
		require.NoError(t, server.Close())
	})

	// Start the server in a separate goroutine
	go func() {
		err := server.Start(ctx)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("Unable to start server: %v", err)
		}
	}()

	// Wait for the server to start
	time.Sleep(1 * time.Second)

	// Register the client with the server
	server.AddTunnelNode(clientTunnelNode)

	// Create a new tunnel client
	client, err := tunnel.NewTunnelClient(ctx,
		tunnel.WithUUID(clientUUID),
		tunnel.WithAuthToken(clientAuthToken),
		tunnel.WithRootCAs(rootCAs),
	)
	require.NoError(t, err)

	t.Cleanup(func() {
		require.NoError(t, client.Close())
	})

	connectCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	t.Cleanup(cancel)

	require.NoError(t, client.Connect(connectCtx))

	// TODO (dpeckett): make some requests from the server side to the client side

	// TODO (dpeckett): make some requests from the client side to the server side
}

func generateKeyPair(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return privateKey, pemData
}
