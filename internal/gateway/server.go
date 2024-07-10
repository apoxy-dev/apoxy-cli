package gateway

import (
	"context"

	"github.com/apoxy-dev/apoxy-cli/internal/gateway/message"
	xdstranslatorrunner "github.com/apoxy-dev/apoxy-cli/internal/gateway/xds/translator/runner"
)

type Config struct {
}

func Serve(ctx context.Context) error {
	xds := new(message.Xds)
	xdsIR := new(message.XdsIR)
	pResources := new(message.ProviderResources)
	defer xds.Close()
	// Start the Xds Translator Service
	// It subscribes to the xdsIR, translates it into xds Resources and publishes it.
	// It also computes the EnvoyPatchPolicy statuses and publishes it.
	xdsTranslatorRunner := xdstranslatorrunner.New(&xdstranslatorrunner.Config{
		XdsIR:             xdsIR,
		Xds:               xds,
		ProviderResources: pResources,
	})
	if err := xdsTranslatorRunner.Start(ctx); err != nil {
		return err
	}

	<-ctx.Done()

	return nil
}
