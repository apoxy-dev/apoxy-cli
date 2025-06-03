package token

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"fmt"
	"net/http"

	"github.com/MicahParks/jwkset"

	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
)

const (
	// JWKSURI is the URI for the JWKS endpoint.
	JWKSURI = "/.well-known/jwks.json"
)

// NewJWKSHandler creates a new HTTP handler that serves the JWK Set for the given public key.
func NewJWKSHandler(publicKeyPEM []byte) (http.HandlerFunc, error) {
	publicKey, err := cryptoutils.ParseEllipticPublicKeyPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	metadata := jwkset.JWKMetadataOptions{
		KID: fingerprint(publicKey),
	}
	jwk, err := jwkset.NewJWKFromKey(publicKey, jwkset.JWKOptions{
		Metadata: metadata,
		Marshal: jwkset.JWKMarshalOptions{
			Private: false,
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}

	jwkSet := jwkset.NewMemoryStorage()
	if err := jwkSet.KeyWrite(context.Background(), jwk); err != nil {
		return nil, fmt.Errorf("failed to write JWK: %w", err)
	}

	return func(w http.ResponseWriter, req *http.Request) {
		resp, err := jwkSet.JSONPublic(req.Context())
		if err != nil {
			http.Error(w, "Failed to get JWK Set JSON", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}, nil
}

func fingerprint(publicKey *ecdsa.PublicKey) string {
	h := sha256.New()
	_, _ = h.Write(publicKey.X.Bytes())
	_, _ = h.Write(publicKey.Y.Bytes())
	return fmt.Sprintf("ES256-%x", h.Sum(nil))
}
