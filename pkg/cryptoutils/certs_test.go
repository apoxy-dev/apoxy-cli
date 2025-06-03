package cryptoutils_test

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
)

func TestGenerateSelfSignedTLSCert(t *testing.T) {
	// Generate a self-signed TLS certificate
	caCert, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)

	// Parse the leaf certificate
	leafCert, err := x509.ParseCertificate(serverCert.Certificate[0])
	require.NoError(t, err)

	// Verify the certificate using the cert pool and hostname "localhost"
	opts := x509.VerifyOptions{
		DNSName: "localhost",
		Roots:   cryptoutils.CertPoolForCertificate(caCert),
	}
	chains, err := leafCert.Verify(opts)
	require.NoError(t, err)
	require.NotEmpty(t, chains)
}

func TestSaveCertificatePEM(t *testing.T) {
	// Generate certificate
	_, serverCert, err := cryptoutils.GenerateSelfSignedTLSCert("localhost")
	require.NoError(t, err)

	// Save cert and key to files
	certsDir := t.TempDir()
	err = cryptoutils.SaveCertificatePEM(serverCert, certsDir, "server", false)
	require.NoError(t, err)

	// Check files exist
	certPath := filepath.Join(certsDir, "server.crt")
	keyPath := filepath.Join(certsDir, "server.key")

	_, err = os.Stat(certPath)
	require.NoError(t, err, "server.crt should exist")

	_, err = os.Stat(keyPath)
	require.NoError(t, err, "server.key should exist")

	// Read and parse certificate
	certPEM, err := os.ReadFile(certPath)
	require.NoError(t, err)
	block, _ := pem.Decode(certPEM)
	require.NotNil(t, block)
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	require.Equal(t, "localhost", parsedCert.Subject.CommonName)

	// Read and parse private key
	keyPEM, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	keyBlock, _ := pem.Decode(keyPEM)
	require.NotNil(t, keyBlock)
	require.Contains(t, keyBlock.Type, "PRIVATE KEY")
}
