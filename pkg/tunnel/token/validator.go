package token

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"log/slog"
	"reflect"
	"strings"

	"github.com/MicahParks/keyfunc/v3"
	"github.com/golang-jwt/jwt/v5"

	"github.com/apoxy-dev/apoxy-cli/pkg/cryptoutils"
)

const (
	// JWKSURI is the URI for the JWKS endpoint.
	JWKSURI = "/.well-known/jwks.json"
)

type JWTValidator interface {
	Validate(tokenStr, subject string) (jwt.Claims, error)
}

func validate(keyFunc jwt.Keyfunc, tokenStr, subject string) (jwt.Claims, error) {
	token, err := jwt.Parse(
		tokenStr,
		keyFunc,
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	tokenClaims := token.Claims
	if tokenClaims == nil {
		return nil, errors.New("failed to parse claims")
	}

	sub, err := tokenClaims.GetSubject()
	if err != nil {
		return nil, errors.New("subject claim not found or invalid")
	}

	if !strings.EqualFold(sub, subject) {
		return nil, fmt.Errorf("token subject %q does not match expected subject %q", sub, subject)
	}

	return tokenClaims, nil
}

// InMemoryValidator validates JWT tokens signed with an ECDSA public key
type InMemoryValidator struct {
	publicKey *ecdsa.PublicKey
}

// NewInMemoryValidator creates a new Validator with the public key.
func NewInMemoryValidator(publicKeyPEM []byte) (*InMemoryValidator, error) {
	publicKey, err := cryptoutils.ParseEllipticPublicKeyPEM(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
	}

	return &InMemoryValidator{publicKey: publicKey}, nil
}

// Validate validates the token is valid and was issued for the specified subject.
func (v *InMemoryValidator) Validate(tokenStr, subject string) (jwt.Claims, error) {
	return validate(func(token *jwt.Token) (any, error) {
		return v.publicKey, nil
	}, tokenStr, subject)
}

type RemoteValidator struct {
	rkf keyfunc.Keyfunc
}

// NewRemoteValidator creates a new Validator with the public key.
func NewRemoteValidator(ctx context.Context, urls []string) (*RemoteValidator, error) {
	fn, err := keyfunc.NewDefaultCtx(ctx, urls)
	if err != nil {
		return nil, fmt.Errorf("failed to create keyfunc: %w", err)
	}
	return &RemoteValidator{rkf: fn}, nil
}

// Validate validates the token is valid and was issued for the specified subject.
func (v *RemoteValidator) Validate(tokenStr, subject string) (jwt.Claims, error) {
	return validate(func(token *jwt.Token) (any, error) {
		key, err := v.rkf.Keyfunc(token)
		if err != nil {
			slog.Error("failed to get key", slog.Any("error", err))
			return nil, err
		}
		if key == nil {
			slog.Error("key is nil")
			return nil, errors.New("key is nil")
		}
		switch key.(type) {
		case *ecdsa.PublicKey:
			return key, nil
		default:
			slog.Error("unsupported key type", "type", reflect.TypeOf(key))
			return nil, errors.New("unsupported key type")
		}
	}, tokenStr, subject)
}
