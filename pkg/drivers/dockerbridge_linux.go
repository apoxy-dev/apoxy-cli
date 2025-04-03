//go:build linux

package drivers

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func getDockerBridgeIP() (string, error) {
	cmd := exec.Command("docker", "network", "inspect", "bridge", "-f", "{{range .IPAM.Config}}{{.Gateway}}{{end}}")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("failed to get docker bridge IP: %w", err)
	}
	ip := strings.TrimSpace(out.String())
	if ip == "" {
		return "", fmt.Errorf("failed to get docker bridge IP: empty output")
	}
	return ip, nil
}
