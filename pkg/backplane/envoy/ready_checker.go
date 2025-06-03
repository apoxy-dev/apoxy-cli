package envoy

import (
	"context"
	"fmt"
	"io"
	"net/http"

	adminv3 "github.com/envoyproxy/go-control-plane/envoy/admin/v3"
	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/apoxy-dev/apoxy/pkg/log"
)

type Listener struct {
	Name    string
	Address corev3.Address
}

type readyChecker struct {
	adminHost string
	listeners []*Listener
}

// NewReadyChecker creates a new readyChecker.
func NewReadyChecker(adminHost string, listeners ...*Listener) *readyChecker {
	return &readyChecker{
		adminHost: adminHost,
		listeners: listeners,
	}
}

// Check implements the HealthChecker interface for the readyChecker.
func (hc *readyChecker) Check(ctx context.Context) (bool, error) {
	if len(hc.listeners) == 0 {
		return true, nil
	}
	if hc.adminHost == "" {
		return false, fmt.Errorf("admin host not set")
	}

	resp, err := http.Get(fmt.Sprintf("http://%s/listeners?format=json", hc.adminHost))
	if err != nil {
		return false, fmt.Errorf("failed to get listeners from admin endpoint: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %w", err)
	}

	adminListeners := adminv3.Listeners{}
	if err := protojson.Unmarshal(body, &adminListeners); err != nil {
		return false, fmt.Errorf("failed to unmarshal listeners: %w", err)
	}

	for _, l := range hc.listeners {
		found := false
		for _, ls := range adminListeners.ListenerStatuses {
			nameMatch := l.Name == "" || l.Name == ls.Name
			if nameMatch &&
				l.Address.GetSocketAddress().GetPortValue() == ls.LocalAddress.GetSocketAddress().GetPortValue() &&
				l.Address.GetSocketAddress().GetProtocol() == ls.LocalAddress.GetSocketAddress().GetProtocol() {
				found = true
				break
			}
			log.Debugf("Listener not matched: name=%s, port=%d, protocol=%s",
				ls.Name,
				ls.LocalAddress.GetSocketAddress().GetPortValue(),
				ls.LocalAddress.GetSocketAddress().GetProtocol())
		}
		if !found {
			log.Infof("Listener not found: name=%s, port=%d, protocol=%s",
				l.Name,
				l.Address.GetSocketAddress().GetPortValue(),
				l.Address.GetSocketAddress().GetProtocol())
			return false, fmt.Errorf("listener not found: name=%s, port=%d, protocol=%s",
				l.Name,
				l.Address.GetSocketAddress().GetPortValue(),
				l.Address.GetSocketAddress().GetProtocol())
		}
	}

	return true, nil
}
