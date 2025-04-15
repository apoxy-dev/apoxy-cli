package token

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy-cli/pkg/cryptoutils"
)

func TestTokenValidator(t *testing.T) {
	privateKeyPEM, publicKeyPEM, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	privateKey, err := cryptoutils.ParseEllipticPrivateKeyPEM(privateKeyPEM)
	require.NoError(t, err)

	validator, err := NewInMemoryValidator(publicKeyPEM)
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
