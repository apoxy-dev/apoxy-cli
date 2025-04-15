package cryptoutils_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy-cli/pkg/cryptoutils"
)

func TestGenerateEllipticKeyPair(t *testing.T) {
	// Generate a new key pair
	privateKeyPEM, publicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	// Attempt to parse the private key
	privateKey, err := cryptoutils.ParseEllipticPrivateKeyPEM(privateKeyPEM)
	require.NoError(t, err)

	// Attempt to parse the public key
	publicKey, err := cryptoutils.ParseEllipticPublicKeyPEM(publicKeyPEM)
	require.NoError(t, err)

	// Check that the public key matches the private key
	assert.Equal(t, privateKey.PublicKey.X, publicKey.X)
}
