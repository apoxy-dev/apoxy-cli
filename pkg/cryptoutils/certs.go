package cryptoutils

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
	"net"
	"os"
	"path/filepath"
	"time"
)

// GenerateSelfSignedTLSCert generates a self-signed TLS certificate.
func GenerateSelfSignedTLSCert(name string) (caCert tls.Certificate, serverCert tls.Certificate, err error) {
	// Generate CA private key.
	caPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		err = fmt.Errorf("failed to generate CA key: %w", err)
		return
	}

	// Create CA certificate template.
	caSerialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	caTemplate := x509.Certificate{
		SerialNumber: caSerialNumber,
		Subject: pkix.Name{
			CommonName:   "Apoxy CA",
			Organization: []string{"Apoxy"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the CA certificate.
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		err = fmt.Errorf("failed to create CA cert: %w", err)
		return
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		err = fmt.Errorf("failed to parse CA cert: %w", err)
		return
	}

	// Encode CA cert to PEM.
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	caKeyBytes, _ := x509.MarshalECPrivateKey(caPriv)
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: caKeyBytes})

	// Create tls.Certificate with server cert and key.
	caCert, err = tls.X509KeyPair(caCertPEM, caKeyPEM)
	if err != nil {
		err = fmt.Errorf("failed to create TLS key pair: %w", err)
		return
	}

	// Generate server private key.
	serverPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		err = fmt.Errorf("failed to generate server key: %w", err)
		return
	}

	// Create server certificate template.
	serverSerialNumber, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serverTemplate := x509.Certificate{
		SerialNumber: serverSerialNumber,
		Subject: pkix.Name{
			CommonName:   name,
			Organization: []string{"Apoxy"},
			Country:      []string{"US"},
			Province:     []string{"CA"},
			Locality:     []string{"San Francisco"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // valid for 1 year
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{name},
	}

	if name == "localhost" {
		serverTemplate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	}

	// Sign server cert with CA cert.
	serverDER, err := x509.CreateCertificate(rand.Reader, &serverTemplate, ca, &serverPriv.PublicKey, caPriv)
	if err != nil {
		err = fmt.Errorf("failed to create server cert: %w", err)
		return
	}

	// Encode server cert and key to PEM.
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverDER})
	serverKeyBytes, _ := x509.MarshalECPrivateKey(serverPriv)
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: serverKeyBytes})

	// Create tls.Certificate with server cert and key.
	serverCert, err = tls.X509KeyPair(serverCertPEM, serverKeyPEM)
	if err != nil {
		err = fmt.Errorf("failed to create TLS key pair: %w", err)
		return
	}

	return
}

// SaveCertificatePEM saves the tls.Certificate into PEM-encoded cert.pem and key.pem files in the given directory.
func SaveCertificatePEM(cert tls.Certificate, dir, name string, publicOnly bool) error {
	// Ensure the output directory exists
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Write the certificate.
	certOut, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s.crt", name)))
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %w", err)
	}
	defer certOut.Close()

	for _, certBytes := range cert.Certificate {
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
			return fmt.Errorf("failed to write cert.pem: %w", err)
		}
	}

	if !publicOnly {
		// Extract private key and write to key.pem
		keyOut, err := os.Create(filepath.Join(dir, fmt.Sprintf("%s.key", name)))
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
	}

	return nil
}

// CertPoolForCertificate creates a new x509.CertPool and adds the given certificate to it.
func CertPoolForCertificate(cert tls.Certificate) *x509.CertPool {
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
	certPool := x509.NewCertPool()
	if !certPool.AppendCertsFromPEM(caPEM) {
		panic("failed to append CA certificate to cert pool")
	}
	return certPool
}
