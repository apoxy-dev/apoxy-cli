package token

import (
	"crypto/ecdsa"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type Issuer struct {
	privateKey *ecdsa.PrivateKey
}

func NewIssuer(privateKey []byte) (*Issuer, error) {
	key, err := jwt.ParseECPrivateKeyFromPEM(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return &Issuer{
		privateKey: key,
	}, nil
}

func (i *Issuer) IssueToken(subj uuid.UUID, ttl time.Duration) (string, jwt.Claims, error) {
	now := time.Now()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, &jwt.RegisteredClaims{
		Subject:   subj.String(),
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
	})

	tokenString, err := token.SignedString(i.privateKey)
	if err != nil {
		return "", nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return tokenString, token.Claims, nil
}
