package gateway

import (
	"context"

	gatewayapirunner "github.com/apoxy-dev/apoxy-cli/internal/gateway/gatewayapi/runner"
	"github.com/apoxy-dev/apoxy-cli/internal/gateway/message"
	xdsserverrunner "github.com/apoxy-dev/apoxy-cli/internal/gateway/xds/server/runner"
	xdstranslatorrunner "github.com/apoxy-dev/apoxy-cli/internal/gateway/xds/translator/runner"
)

type server struct {
	Resources *message.ProviderResources
}

// NewServer creates a new Gateway API server.
func NewServer() *server {
	return &server{
		Resources: new(message.ProviderResources),
	}
}

func (s *server) Run(ctx context.Context) error {
	xdsIR := new(message.XdsIR)
	// Start the GatewayAPI Translator Runner
	// It subscribes to the provider resources, translates it to xDS IR
	// and infra IR resources and publishes them.
	gwRunner := gatewayapirunner.New(&gatewayapirunner.Config{
		ProviderResources: s.Resources,
		XdsIR:             xdsIR,
	})
	if err := gwRunner.Start(ctx); err != nil {
		return err
	}

	xds := new(message.Xds)
	defer xds.Close()
	// Start the Xds Translator Service
	// It subscribes to the xdsIR, translates it into xds Resources and publishes it.
	// It also computes the EnvoyPatchPolicy statuses and publishes it.
	xdsTranslatorRunner := xdstranslatorrunner.New(&xdstranslatorrunner.Config{
		ProviderResources: s.Resources,
		XdsIR:             xdsIR,
		Xds:               xds,
	})
	if err := xdsTranslatorRunner.Start(ctx); err != nil {
		return err
	}

	xdsServerRunner := xdsserverrunner.New(&xdsserverrunner.Config{
		Xds: xds,
	})
	if err := xdsServerRunner.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}
