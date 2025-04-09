package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

// GenerateSelfSignedTLSCert generates a self-signed TLS certificate and a CertPool that trusts it.
func GenerateSelfSignedTLSCert() (tls.Certificate, *x509.CertPool, error) {
	// Generate a private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	// Create a certificate template
	serialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   "localhost",
			Organization: []string{"My Org"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	// PEM encode the certificate and key
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})

	// Load into tls.Certificate
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, err
	}

	// Create a CertPool with the certificate to use as a trusted root
	certPool := x509.NewCertPool()
	ok := certPool.AppendCertsFromPEM(certPEM)
	if !ok {
		return tls.Certificate{}, nil, err
	}

	return cert, certPool, nil
}

// SaveTLSCertificatePEM saves the tls.Certificate into PEM-encoded cert.pem and key.pem files in the given directory.
func SaveTLSCertificatePEM(cert tls.Certificate, dir string) error {
	// Ensure the output directory exists
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write the certificate to cert.pem
	certOut, err := os.Create(filepath.Join(dir, "cert.pem"))
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %w", err)
	}
	defer certOut.Close()

	for _, certBytes := range cert.Certificate {
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
			return fmt.Errorf("failed to write cert.pem: %w", err)
		}
	}

	// Extract private key and write to key.pem
	keyOut, err := os.Create(filepath.Join(dir, "key.pem"))
	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %w", err)
	}
	defer keyOut.Close()

	var keyBlock *pem.Block
	switch key := cert.PrivateKey.(type) {
	case *ecdsa.PrivateKey:
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return fmt.Errorf("failed to marshal EC private key: %w", err)
		}
		keyBlock = &pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	case *rsa.PrivateKey:
		der := x509.MarshalPKCS1PrivateKey(key)
		keyBlock = &pem.Block{Type: "RSA PRIVATE KEY", Bytes: der}
	default:
		return fmt.Errorf("unsupported private key type: %T", cert.PrivateKey)
	}

	if err := pem.Encode(keyOut, keyBlock); err != nil {
		return fmt.Errorf("failed to write key.pem: %w", err)
	}

	return nil
}
