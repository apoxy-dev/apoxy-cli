package socksproxy_test

import (
	"context"
	"net/http"
	"os"
	"testing"

	"github.com/apoxy-dev/apoxy-cli/pkg/network"
	"github.com/apoxy-dev/apoxy-cli/pkg/socksproxy"
	"github.com/stretchr/testify/require"
	proxyclient "golang.org/x/net/proxy"
)

func TestProxyServer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	srv := socksproxy.NewServer("localhost:9050", network.Host())
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
