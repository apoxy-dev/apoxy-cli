package socksproxy_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"testing"

	"github.com/dpeckett/network"
	"github.com/dpeckett/network/nettest"
	"github.com/stretchr/testify/require"
	proxyclient "golang.org/x/net/proxy"

	"github.com/apoxy-dev/apoxy-cli/pkg/socksproxy"
)

func TestProxyServer(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stack, err := nettest.NewStack(netip.MustParseAddr("100.64.0.1"), "")
	require.NoError(t, err)
	t.Cleanup(stack.Close)

	privateNet := network.Netstack(stack.Stack, stack.NICID, nil)
	publicNet := network.Host()

	srv := socksproxy.NewServer("localhost:9050", privateNet, publicNet)
	t.Cleanup(func() {
		require.NoError(t, srv.Close())
	})

	go func() {
		if err := srv.ListenAndServe(ctx); err != nil {
			os.Exit(1)
		}
	}()

	dialer, err := proxyclient.SOCKS5("tcp", srv.Addr, nil, proxyclient.Direct)
	require.NoError(t, err)

	client := &http.Client{
		Transport: &http.Transport{
			Dial: dialer.Dial,
		},
	}

	resp, err := client.Get("https://example.com")
	require.NoError(t, err)
	t.Cleanup(func() {
		require.NoError(t, resp.Body.Close())
	})

	require.Equal(t, http.StatusOK, resp.StatusCode)
}
