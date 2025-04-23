//go:build linux

package router

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/apoxy-dev/apoxy-cli/pkg/connip"
)

func TestNetlinkRouterMock(t *testing.T) {
	// This is a mock test that doesn't actually create routes
	// but validates the struct and interface implementation

	r := &NetlinkRouter{}

	// Test that it implements the Router interface
	var _ Router = r

	// Test Start method existence
	assert.NotPanics(t, func() {
		startMethod := reflect.ValueOf(r).MethodByName("Start")
		assert.True(t, startMethod.IsValid(), "Start method should exist")
	})

	// Test GetTunnelDevice method existence
	assert.NotPanics(t, func() {
		getTunnelDeviceMethod := reflect.ValueOf(r).MethodByName("GetTunnelDevice")
		assert.True(t, getTunnelDeviceMethod.IsValid(), "GetTunnelDevice method should exist")
	})

	conn := connip.NewMuxedConnection()

	// Test AddPeer
	prefix := netip.MustParsePrefix("fd00::1/128")
	_, err := r.AddPeer(prefix, conn)
	// Should fail since we didn't initialize the link
	assert.Error(t, err)

	// Test RemovePeer
	err = r.RemovePeer(prefix)
	// Should fail since we didn't initialize the link
	assert.Error(t, err)

	// Test Close
	err = r.Close()
	require.NoError(t, err)
}
