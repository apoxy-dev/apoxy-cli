package wireguard_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.zx2c4.com/wireguard/conn"

	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"
)

func TestTrySTUN(t *testing.T) {
	bind := conn.NewDefaultBind()

	t.Run("Success", func(t *testing.T) {
		ctx := context.Background()
		addrPort, err := wireguard.TryStun(ctx, bind, 51823, "stun.l.google.com:19302", "stun.cloudflare.com:3478")
		require.NoError(t, err)

		require.NotEmpty(t, addrPort.String())
		require.False(t, addrPort.Addr().IsPrivate())
	})

	t.Run("Timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		t.Cleanup(cancel)

		addrPort, err := wireguard.TryStun(ctx, bind, 51823, "example.com:1234")
		require.Error(t, err)

		require.Zero(t, addrPort)
		require.True(t, errors.Is(err, context.DeadlineExceeded))
	})
}
