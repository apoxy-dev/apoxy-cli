package router

import (
	"context"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/connection"
)

// MockRouter implements the Router interface for testing purposes.
type MockRouter struct {
	lock          sync.Mutex
	routes        map[string]netip.Prefix
	tunDev        tun.Device
	mux           *connection.MuxedConnection
	startErr      error
	getTunDevErr  error
	addPeerErr    error
	removePeerErr error
	closeErr      error
}

// NewMockRouter creates a new MockRouter for testing.
func NewMockRouter() *MockRouter {
	return &MockRouter{
		routes: make(map[string]netip.Prefix),
		mux:    connection.NewMuxedConnection(),
	}
}

// SetTunnelDevice sets the mock tunnel device.
func (m *MockRouter) SetTunnelDevice(dev tun.Device) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.tunDev = dev
}

// SetStartError sets the error that will be returned by Start.
func (m *MockRouter) SetStartError(err error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.startErr = err
}

// SetGetTunnelDeviceError sets the error that will be returned by GetTunnelDevice.
func (m *MockRouter) SetGetTunnelDeviceError(err error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.getTunDevErr = err
}

// SetAddPeerError sets the error that will be returned by AddPeer.
func (m *MockRouter) SetAddPeerError(err error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.addPeerErr = err
}

// SetRemovePeerError sets the error that will be returned by RemovePeer.
func (m *MockRouter) SetRemovePeerError(err error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.removePeerErr = err
}

// SetCloseError sets the error that will be returned by Close.
func (m *MockRouter) SetCloseError(err error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.closeErr = err
}

// GetRoutes returns all routes currently added to the router.
func (m *MockRouter) GetRoutes() []netip.Prefix {
	m.lock.Lock()
	defer m.lock.Unlock()

	routes := make([]netip.Prefix, 0, len(m.routes))
	for _, route := range m.routes {
		routes = append(routes, route)
	}
	return routes
}

// GetMuxedConnection returns the muxed connection for testing.
func (m *MockRouter) GetMuxedConnection() *connection.MuxedConnection {
	return m.mux
}

// Start is a mock implementation that satisfies the Router interface.
func (m *MockRouter) Start(ctx context.Context) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.startErr != nil {
		return m.startErr
	}

	// Simply block until context is done
	<-ctx.Done()
	return nil
}

// AddPeer adds a peer route to the tunnel.
func (m *MockRouter) AddPeer(peer netip.Prefix, conn connection.Connection) (netip.Addr, []netip.Prefix, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.addPeerErr != nil {
		return netip.Addr{}, nil, m.addPeerErr
	}

	m.routes[peer.String()] = peer
	return peer.Addr(), []netip.Prefix{peer}, nil
}

// RemovePeer removes a peer route from the tunnel.
func (m *MockRouter) RemovePeer(peer netip.Prefix) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.removePeerErr != nil {
		return m.removePeerErr
	}

	delete(m.routes, peer.String())
	return nil
}

// Close releases any resources associated with the router.
func (m *MockRouter) Close() error {
	m.lock.Lock()
	defer m.lock.Unlock()

	if m.closeErr != nil {
		return m.closeErr
	}

	if m.tunDev != nil {
		if err := m.tunDev.Close(); err != nil {
			return err
		}
		m.tunDev = nil
	}

	m.routes = make(map[string]netip.Prefix)
	return nil
}
