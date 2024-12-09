//go:build darwin
// +build darwin

package drivers

func getDockerBridgeIP() (string, error) {
	return "host.docker.internal", nil
}
