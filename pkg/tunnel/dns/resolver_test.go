package dns

import (
	"context"
	"net"
	"net/netip"
	"testing"

	cdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
)

// testResponseWriter is a mock implementation of the dns.ResponseWriter interface.
type testResponseWriter struct {
	msg *cdns.Msg
}

func (w *testResponseWriter) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 12345))
}
func (w *testResponseWriter) RemoteAddr() net.Addr {
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), 12345))
}
func (w *testResponseWriter) WriteMsg(msg *cdns.Msg) error {
	w.msg = msg
	return nil
}
func (w *testResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (w *testResponseWriter) Close() error              { return nil }
func (w *testResponseWriter) TsigStatus() error         { return nil }
func (w *testResponseWriter) TsigTimersOnly(bool)       {}
func (w *testResponseWriter) Hijack()                   {}

// nextHandler is a mock implementation of the plugin.Handler interface.
type nextHandler struct {
	called bool
	code   int
	err    error
}

func (h *nextHandler) Name() string {
	return "nextHandler"
}

func (h *nextHandler) ServeDNS(ctx context.Context, w cdns.ResponseWriter, r *cdns.Msg) (int, error) {
	h.called = true
	return h.code, h.err
}

func TestTunnelNodeDNSReconciler(t *testing.T) {
	// Create a mock TunnelNode
	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
		Status: corev1alpha.TunnelNodeStatus{
			Agents: []corev1alpha.AgentStatus{
				{
					Name:           "agent1",
					ConnectedAt:    ptr.To(metav1.Now()),
					PrivateAddress: "fd00::1",
					AgentAddress:   "192.168.1.100",
				},
			},
		},
	}

	scheme := runtime.NewScheme()
	err := corev1alpha.Install(scheme)
	require.NoError(t, err)

	// Create a fake client with the TunnelNode
	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tunnelNode).
		Build()

	// Create a reconciler
	reconciler := NewTunnelNodeDNSReconciler(client)

	// Test the reconcile logic
	t.Run("Reconcile", func(t *testing.T) {
		req := reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: "test-node",
			},
		}

		// Reconcile the resource.
		result, err := reconciler.reconcile(context.Background(), req)
		require.NoError(t, err)
		assert.Equal(t, ctrl.Result{}, result)

		// Verify the cache was updated
		addr, ok := reconciler.nameCache.Get("test-node")
		require.True(t, ok)
		expectedAddrs := sets.New(netip.MustParseAddr("fd00::1"))
		assert.Equal(t, expectedAddrs, addr)

		// Test handling of non-existent resources.
		req = reconcile.Request{
			NamespacedName: types.NamespacedName{
				Name: "non-existent",
			},
		}

		// Add a dummy entry to the cache.
		reconciler.nameCache.Set("non-existent", sets.New(netip.MustParseAddr("fd00::2")))

		// Reconcile the non-existent resource.
		result, err = reconciler.reconcile(context.Background(), req)
		assert.NoError(t, err) // Should handle not found gracefully
		assert.Equal(t, ctrl.Result{}, result)
	})
}

func TestTunnelNodeDNSServer(t *testing.T) {
	// Create a mock TunnelNode
	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-node",
		},
		Status: corev1alpha.TunnelNodeStatus{
			Agents: []corev1alpha.AgentStatus{
				{
					Name:           "agent1",
					ConnectedAt:    ptr.To(metav1.Now()),
					PrivateAddress: "fd00::1",
					AgentAddress:   "192.168.1.100",
				},
				{
					Name:           "agent3",
					ConnectedAt:    ptr.To(metav1.Now()),
					PrivateAddress: "10.0.0.1",
					AgentAddress:   "192.168.1.102",
				},
			},
		},
	}

	// Create a fake client with the TunnelNode
	scheme := runtime.NewScheme()
	err := corev1alpha.Install(scheme)
	require.NoError(t, err)

	client := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(tunnelNode).
		Build()

	// Create a resolver
	resolver := NewTunnelNodeDNSReconciler(client)

	// Add the TunnelNode to the cache
	resolver.nameCache.Set(tunnelNode.Name, sets.New(netip.MustParseAddr("fd00::1"), netip.MustParseAddr("10.0.0.1")))

	// Test the ServeDNS method
	t.Run("ServeDNS - valid IPv6 query", func(t *testing.T) {
		// Create a DNS message
		msg := new(cdns.Msg)
		msg.SetQuestion("test-node.tun.apoxy.net.", cdns.TypeAAAA)

		// Create a response writer
		rw := &testResponseWriter{}

		// Call the handler
		code, err := resolver.serveDNS(context.Background(), nil, rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)

		// Verify the response
		require.NotNil(t, rw.msg)
		require.Len(t, rw.msg.Answer, 1)
		aaaa, ok := rw.msg.Answer[0].(*cdns.AAAA)
		require.True(t, ok, "Answer should be AAAA record")
		expectedIP := netip.MustParseAddr("fd00::1").String()
		assert.Equal(t, expectedIP, aaaa.AAAA.String())
	})

	t.Run("ServeDNS - valid IPv4 query", func(t *testing.T) {
		// Create a DNS message
		msg := new(cdns.Msg)
		msg.SetQuestion("test-node.tun.apoxy.net.", cdns.TypeA)

		// Create a response writer
		rw := &testResponseWriter{}

		// Call the handler
		code, err := resolver.serveDNS(context.Background(), nil, rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)

		// Verify the response
		require.NotNil(t, rw.msg)
		require.Len(t, rw.msg.Answer, 1)
		a, ok := rw.msg.Answer[0].(*cdns.A)
		require.True(t, ok, "Answer should be A record")
		expectedIP := netip.MustParseAddr("10.0.0.1").String()
		assert.Equal(t, expectedIP, a.A.String())
	})

	t.Run("ServeDNS - non-matching domain", func(t *testing.T) {
		next := &nextHandler{code: cdns.RcodeSuccess}
		handler := resolver.Resolver(next)

		// Create a DNS message
		msg := new(cdns.Msg)
		msg.SetQuestion("example.com.", cdns.TypeA)

		// Create a response writer
		rw := &testResponseWriter{}

		// Call the handler
		code, err := handler.ServeDNS(context.Background(), rw, msg)
		require.NoError(t, err)
		assert.Equal(t, 0, code) // Should be handled by the next plugin
	})

	// Test the Resolver function
	t.Run("Resolver", func(t *testing.T) {
		next := &nextHandler{code: cdns.RcodeSuccess}
		handler := resolver.Resolver(next)

		// Create a DNS message for a non-existent agent
		msg := new(cdns.Msg)
		msg.SetQuestion("non-existent.test-node.tun.apoxy.net.", cdns.TypeA)

		// Create a response writer
		rw := &testResponseWriter{}

		// Call the handler
		code, err := handler.ServeDNS(context.Background(), rw, msg)
		require.NoError(t, err)
		assert.Equal(t, cdns.RcodeSuccess, code)
		assert.True(t, next.called, "Next handler should be called")
	})
}
