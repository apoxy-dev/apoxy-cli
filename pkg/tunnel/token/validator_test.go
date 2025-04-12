package token

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestTokenValidator(t *testing.T) {
	privateKey, publicKey := generateKeyPair(t)

	validator, err := NewInMemoryValidator(publicKey)
	require.NoError(t, err)

	t.Run("Valid", func(t *testing.T) {
		subject := "1234567890"
		authToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"sub": subject,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 5).Unix(),
		}).SignedString(privateKey)
		require.NoError(t, err)

		_, err = validator.Validate(authToken, subject)
		require.NoError(t, err)
	})

	t.Run("Different Subject", func(t *testing.T) {
		authToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"sub": "1234567890",
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(time.Minute * 5).Unix(),
		}).SignedString(privateKey)
		require.NoError(t, err)

		_, err = validator.Validate(authToken, "a-different-subject")
		require.Error(t, err)
	})

	t.Run("Expired", func(t *testing.T) {
		subject := "1234567890"
		authToken, err := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
			"sub": subject,
			"iat": time.Now().Add(-time.Hour).Unix(),
			"exp": time.Now().Add(-time.Minute).Unix(),
		}).SignedString(privateKey)
		require.NoError(t, err)

		_, err = validator.Validate(authToken, subject)
		require.Error(t, err)
	})
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
