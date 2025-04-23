package router

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/apoxy-dev/apoxy-cli/pkg/connip"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestNetstackRouter(t *testing.T) {
	r, err := NewNetstackRouter()
	require.NoError(t, err)
	require.NotNil(t, r)

	// Test Start method with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	g, ctx := errgroup.WithContext(ctx)
	g.Go(func() error {
		return r.Start(ctx)
	})

	// Wait for context timeout
	time.Sleep(110 * time.Millisecond)

	// Verify Start returns after context is done
	err = g.Wait()
	assert.NoError(t, err)

	// Test AddPeer
	prefix := netip.MustParsePrefix("fd00::1/128")
	conn := connip.NewMuxedConnection()
	_, err = r.AddPeer(prefix, conn)
	// Should fail since the netstack implementation is not complete
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")

	// Test RemovePeer
	err = r.RemovePeer(prefix)
	// Should fail since the netstack implementation is not complete
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not implemented")

	// Test Close
	err = r.Close()
	require.NoError(t, err)
}
