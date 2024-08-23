package gateway

import (
	corev1 "k8s.io/api/core/v1"
	gwapiv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/apoxy-dev/apoxy-cli/internal/gateway/gatewayapi"
)

// terminatesTLS returns true if the provided gateway contains a listener configured
// for TLS termination.
func terminatesTLS(listener *gwapiv1.Listener) bool {
	if listener.TLS != nil &&
		(listener.Protocol == gwapiv1.HTTPSProtocolType ||
			listener.Protocol == gwapiv1.TLSProtocolType) &&
		listener.TLS.Mode != nil &&
		*listener.TLS.Mode == gwapiv1.TLSModeTerminate {
		return true
	}
	return false
}

// refsSecret returns true if ref refers to a Secret.
func refsSecret(ref *gwapiv1.SecretObjectReference) bool {
	return (ref.Group == nil || *ref.Group == corev1.GroupName) &&
		(ref.Kind == nil || *ref.Kind == gatewayapi.KindSecret)
}
