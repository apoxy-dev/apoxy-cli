package drivers

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/google/uuid"

	"github.com/apoxy-dev/apoxy-cli/build"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	dockerutils "github.com/apoxy-dev/apoxy-cli/pkg/utils/docker"
)

const (
	tunnelProxyContainerNamePrefix = "apoxy-tunnelproxy-"
	tunnelProxyImageRepo           = "tunnelproxy"
)

// TunnelProxyDockerDriver implements the Driver interface for Docker.
type TunnelProxyDockerDriver struct {
	dockerDriverBase
}

// NewTunnelProxyDockerDriver creates a new Docker driver for tunnelproxy.
func NewTunnelProxyDockerDriver() *TunnelProxyDockerDriver {
	return &TunnelProxyDockerDriver{}
}

// generateSelfSignedCert creates a self-signed certificate and private key.
func generateSelfSignedCert(certPath, keyPath string) error {
	// Create a new private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Prepare certificate template
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour) // Valid for 1 year

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Apoxy Self-Signed Certificate"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	// Create the self-signed certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
		return fmt.Errorf("failed to create directory for cert: %w", err)
	}

	// Write the certificate to disk
	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %w", err)
	}
	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("failed to write data to cert.pem: %w", err)
	}

	// Write the private key to disk
	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %w", err)
	}
	defer keyOut.Close()

	privBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	}

	if err := pem.Encode(keyOut, privBlock); err != nil {
		return fmt.Errorf("failed to write data to key.pem: %w", err)
	}

	return nil
}

// Start implements the Driver interface.
func (d *TunnelProxyDockerDriver) Start(
	ctx context.Context,
	orgID uuid.UUID,
	proxyName string,
	opts ...Option,
) (string, error) {
	setOpts := DefaultOptions()
	for _, opt := range opts {
		opt(setOpts)
	}

	if err := d.Init(ctx, opts...); err != nil {
		return "", err
	}

	imageRef := d.ImageRef(tunnelProxyImageRepo)
	cname, found, err := dockerutils.Collect(
		ctx,
		tunnelProxyContainerNamePrefix,
		imageRef,
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.tunnelproxy", proxyName),
	)
	if err != nil {
		return "", err
	} else if found {
		log.Infof("Container %s already running", cname)
		return cname, nil
	}

	if err := exec.CommandContext(ctx, "docker", "image", "inspect", imageRef).Run(); err != nil {
		if err := exec.CommandContext(ctx, "docker", "pull", imageRef).Run(); err != nil {
			return "", fmt.Errorf("failed to pull image %s: %w", imageRef, err)
		}
	}

	certsDir := filepath.Join(os.TempDir(), "apoxy-certs")
	certPath := filepath.Join(certsDir, "cert.pem")
	keyPath := filepath.Join(certsDir, "key.pem")

	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create certs directory: %w", err)
	}

	log.Infof("Generating self-signed certificates at %s and %s", certPath, keyPath)

	if err := generateSelfSignedCert(certPath, keyPath); err != nil {
		return "", fmt.Errorf("failed to generate self-signed certificates: %w", err)
	}

	log.Infof("Starting container %s", cname)

	cmd := exec.CommandContext(ctx,
		"docker", "run",
		"--pull="+d.PullPolicy(),
		"--detach",
		"--name", cname,
		"--label", "org.apoxy.project_id="+orgID.String(),
		"--label", "org.apoxy.tunnelproxy="+proxyName,
		"--privileged",
		"--network", dockerutils.NetworkName,
		"--volume", fmt.Sprintf("%s:/etc/apoxy/certs", certsDir),
		"-p", "9443:8443/udp",
	)

	apiserverAddr := setOpts.APIServerAddr
	if apiserverAddr == "" {
		apiServerHost, err := getDockerBridgeIP()
		if err != nil {
			return "", fmt.Errorf("failed to get docker bridge IP: %w", err)
		}
		apiserverAddr = fmt.Sprintf("%s:8443", apiServerHost)
	}

	cmd.Args = append(cmd.Args, imageRef)
	cmd.Args = append(cmd.Args, []string{
		"--apiserver_addr=" + apiserverAddr,
	}...)
	if build.IsDev() {
		cmd.Args = append(cmd.Args, "--dev")
	}
	cmd.Args = append(cmd.Args, setOpts.Args...)

	log.Debugf("Running command: %v", cmd.String())

	if err := cmd.Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("failed to start tunnel proxy: %s", execErr.Stderr)
		}
		return "", fmt.Errorf("failed to start tunnel proxy: %w", err)
	}

	if err := dockerutils.WaitForStatus(ctx, cname, "running"); err != nil {
		return "", fmt.Errorf("failed to start tunnel proxy: %w", err)
	}

	return cname, nil
}

// Stop implements the Driver interface.
func (d *TunnelProxyDockerDriver) Stop(orgID uuid.UUID, proxyName string) {
	ctx, _ := context.WithTimeout(context.Background(), 30*time.Second)
	cname, found, err := dockerutils.Collect(
		ctx,
		tunnelProxyContainerNamePrefix,
		d.ImageRef(tunnelProxyImageRepo),
		dockerutils.WithLabel("org.apoxy.project_id", orgID.String()),
		dockerutils.WithLabel("org.apoxy.tunnelproxy", proxyName),
	)
	if err != nil {
		log.Errorf("Error stopping Docker container: %v", err)
	} else if !found {
		log.Infof("Container %s wasn't found running", cname)
		return
	}
	log.Infof("Stopping container %s", cname)
	cmd := exec.CommandContext(ctx,
		"docker", "rm", "-f", cname,
	)
	if err := cmd.Run(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			log.Errorf("failed to stop tunnel proxy: %s", execErr.Stderr)
		} else {
			log.Errorf("failed to stop tunnel proxy: %v", err)
		}
	}
}

// GetAddr implements the Driver interface.
func (d *TunnelProxyDockerDriver) GetAddr(ctx context.Context) (string, error) {
	cname, found, err := dockerutils.Collect(
		ctx,
		tunnelProxyContainerNamePrefix,
		d.ImageRef(tunnelProxyImageRepo),
	)
	if err != nil {
		return "", err
	} else if !found {
		return "", fmt.Errorf("tunnel proxy not found")
	}
	return cname, nil
}
