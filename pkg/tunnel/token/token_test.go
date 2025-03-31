package token_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"apoxy.dev/masque-tunnel/internal/token"
)

func TestTokenValidator(t *testing.T) {
	privateKey, publicKeyPath := generateKeyPair(t)

	validator, err := token.NewValidator(publicKeyPath)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		subject := "1234567890"
		authToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"sub": subject,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 5).Unix(),
		}).SignedString(privateKey)
		require.NoError(t, err)

		require.NoError(t, validator.Validate(authToken, subject))
	})

	t.Run("Different Subject", func(t *testing.T) {
		authToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"sub": "1234567890",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 5).Unix(),
		}).SignedString(privateKey)
		require.NoError(t, err)

		require.Error(t, validator.Validate(authToken, "a-different-subject"))
	})

	t.Run("Expired", func(t *testing.T) {
		subject := "1234567890"
		authToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"sub": subject,
			"iat": time.Now().Add(-time.Hour).Unix(),
			"exp": time.Now().Add(-time.Minute).Unix(),
		}).SignedString(privateKey)
		require.NoError(t, err)

		require.Error(t, validator.Validate(authToken, subject))
	})
}

func generateKeyPair(t *testing.T) (*ecdsa.PrivateKey, string) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)

	pemData := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	publicKeyPath := filepath.Join(t.TempDir(), "jwt.pem")
	err = os.WriteFile(publicKeyPath, pemData, 0o600)
	require.NoError(t, err)

	return privateKey, publicKeyPath
}
