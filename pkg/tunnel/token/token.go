package token

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

// Validator validates JWT tokens signed with an ECDSA public key
type Validator struct {
	publicKey *ecdsa.PublicKey
}

// NewValidator creates a new Validator with the public key.
func NewValidator(pubKey []byte) (*Validator, error) {
	block, _ := pem.Decode(pubKey)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing public key")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA public key: %w", err)
	}

	ecdsaPublicKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	return &Validator{publicKey: ecdsaPublicKey}, nil
}

// Validate validates the token is valid and was issued for the specified subject.
func (v *Validator) Validate(tokenStr, subject string) error {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		return v.publicKey, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodES256.Alg()}),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return fmt.Errorf("failed to parse token: %w", err)
	}

	if !token.Valid {
		return errors.New("invalid token")
	}

	tokenClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("failed to parse claims")
	}

	tokenSubject, ok := tokenClaims["sub"].(string)
	if !ok {
		return errors.New("subject claim not found or invalid")
	}

	if strings.ToLower(tokenSubject) != strings.ToLower(subject) {
		return fmt.Errorf("token subject %q does not match expected subject %q", tokenSubject, subject)
	}

	return nil
}
