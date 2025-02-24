package stunserver_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"testing"

	"github.com/apoxy-dev/apoxy-cli/pkg/stunserver"
	"github.com/pion/stun/v2"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestListenAndServe(t *testing.T) {
	if testing.Verbose() {
		slog.SetLogLoggerLevel(slog.LevelDebug)
	}

	g, ctx := errgroup.WithContext(context.Background())

	g.Go(func() error {
		return stunserver.ListenAndServe(ctx, "localhost:3478")
	})

	g.Go(func() error {
		client, err := stun.DialURI(&stun.URI{
			Scheme:   stun.SchemeTypeSTUN,
			Host:     "localhost",
			Port:     3478,
			Username: "apoxy",
			Password: "apoxy",
		}, &stun.DialConfig{})
		if err != nil {
			return fmt.Errorf("failed to create STUN client: %w", err)
		}
		defer client.Close()

		var (
			requestErr error
			nonce      stun.Nonce
			realm      stun.Realm
		)

		// First request should error.
		request := stun.MustBuild(stun.BindingRequest, stun.TransactionID, stun.Fingerprint)
		if err = client.Do(request, func(event stun.Event) {
			if event.Error != nil {
				requestErr = fmt.Errorf("got event with error: %w", event.Error)
			}
			response := event.Message
			if response.Type != stun.BindingError {
				requestErr = fmt.Errorf("unexpected response type: %v", response.Type)
			}
			var errCode stun.ErrorCodeAttribute
			if codeErr := errCode.GetFrom(response); codeErr != nil {
				requestErr = fmt.Errorf("failed to get error code: %w", codeErr)
			}
			if errCode.Code != stun.CodeUnauthorized {
				requestErr = fmt.Errorf("unexpected error code: %v", errCode)
			}
			if parseErr := response.Parse(&nonce, &realm); parseErr != nil {
				requestErr = fmt.Errorf("failed to parse: %w", parseErr)
			}
		}); err != nil {
			return fmt.Errorf("failed to perform STUN operation: %w", err)
		}
		if requestErr != nil {
			return requestErr
		}

		// Second request should authenticate and succeed.
		request = stun.MustBuild(stun.TransactionID, stun.BindingRequest,
			stun.NewUsername("apoxy"), nonce, realm,
			stun.NewLongTermIntegrity("apoxy", realm.String(), "apoxy"),
			stun.Fingerprint,
		)
		if err := client.Do(request, func(res stun.Event) {
			requestErr = nil
			if res.Error != nil || res.Message == nil {
				requestErr = fmt.Errorf("invalid STUN response: %w", res.Error)
				return
			}

			var xorAddr stun.XORMappedAddress
			if err := xorAddr.GetFrom(res.Message); err != nil {
				requestErr = fmt.Errorf("failed to get XOR-Mapped-Address: %w", err)
				return
			}

			t.Logf("Got STUN response: %v", xorAddr.String())
		}); err != nil {
			return fmt.Errorf("failed to perform STUN operation: %w", err)
		}
		if requestErr != nil {
			return requestErr
		}

		return context.Canceled
	})

	if err := g.Wait(); err != nil && !errors.Is(err, context.Canceled) {
		require.NoError(t, err)
	}
}
