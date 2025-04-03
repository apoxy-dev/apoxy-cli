package drivers

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"k8s.io/client-go/rest"
)

// PortForwarder provides port forwarding capabilities for containers.
type PortForwarder struct {
	clientConfig *rest.Config
	proxyName    string
	replicaName  string
	containerID  string
	cmd          *exec.Cmd
}

// NewPortForwarder creates a new port forwarder.
func NewPortForwarder(clientConfig *rest.Config, proxyName, replicaName, containerID string) (*PortForwarder, error) {
	return &PortForwarder{
		clientConfig: clientConfig,
		proxyName:    proxyName,
		replicaName:  replicaName,
		containerID:  containerID,
	}, nil
}

// Run starts port forwarding.
func (f *PortForwarder) Run(ctx context.Context) error {
	if f.cmd != nil {
		return fmt.Errorf("port forwarder is already running")
	}

	// Get container IP
	cmd := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", f.containerID)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get container IP: %w", err)
	}
	containerIP := strings.TrimSpace(string(out))
	if containerIP == "" {
		return fmt.Errorf("failed to get container IP: empty output")
	}

	// Start socat for port forwarding
	f.cmd = exec.CommandContext(ctx, "socat", "TCP-LISTEN:8088,fork,reuseaddr", fmt.Sprintf("TCP:%s:8088", containerIP))
	f.cmd.Stdout = os.Stdout
	f.cmd.Stderr = os.Stderr

	log.Infof("Starting port forwarding for %s to %s:8088", f.containerID, containerIP)
	if err := f.cmd.Start(); err != nil {
		return fmt.Errorf("failed to start port forwarding: %w", err)
	}

	// Wait for port to be available
	for i := 0; i < 10; i++ {
		conn, err := net.DialTimeout("tcp", "localhost:8088", 100*time.Millisecond)
		if err == nil {
			conn.Close()
			log.Infof("Port forwarding is ready")
			break
		}
		time.Sleep(500 * time.Millisecond)
	}

	// Wait for the command to complete
	go func() {
		err := f.cmd.Wait()
		if err != nil && ctx.Err() == nil {
			log.Errorf("Port forwarding exited with error: %v", err)
		}
		f.cmd = nil
	}()

	return nil
}

// Stop stops port forwarding.
func (f *PortForwarder) Stop() {
	if f.cmd != nil && f.cmd.Process != nil {
		log.Infof("Stopping port forwarding")
		if err := f.cmd.Process.Kill(); err != nil {
			log.Errorf("Failed to stop port forwarding: %v", err)
		}
		f.cmd = nil
	}
}
