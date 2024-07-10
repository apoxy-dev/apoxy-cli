// Copyright Envoy Gateway Authors
// SPDX-License-Identifier: Apache-2.0
// The full text of the Apache license is available in the LICENSE file at
// the root of the repo.

package runner

import (
	"context"
	"log/slog"

	"github.com/apoxy-dev/apoxy-cli/internal/gateway/ir"
	"github.com/apoxy-dev/apoxy-cli/internal/gateway/message"
	"github.com/apoxy-dev/apoxy-cli/internal/gateway/xds/translator"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

const (
	xdsRuner = "xds-runner"
)

type Config struct {
	Logger            *slog.Logger
	XdsIR             *message.XdsIR
	Xds               *message.Xds
	ProviderResources *message.ProviderResources
}

type Runner struct {
	Config
}

func New(cfg *Config) *Runner {
	return &Runner{Config: *cfg}
}

func (r *Runner) Name() string {
	return xdsRuner
}

// Start starts the xds-translator runner
func (r *Runner) Start(ctx context.Context) (err error) {
	r.Logger = log.DefaultLogger.With("runner", r.Name())
	go r.subscribeAndTranslate(ctx)
	r.Logger.Info("started")
	return
}

func (r *Runner) subscribeAndTranslate(ctx context.Context) {
	// Subscribe to resources
	message.HandleSubscription(message.Metadata{Runner: r.Name(), Message: "xds-ir"}, r.XdsIR.Subscribe(ctx),
		func(update message.Update[string, *ir.Xds], errChan chan error) {
			r.Logger.Info("received an update")
			key := update.Key
			val := update.Value

			if update.Delete {
				r.Xds.Delete(key)
			} else {
				// Translate to xds resources
				t := &translator.Translator{}

				result, err := t.Translate(val)
				if err != nil {
					r.Logger.Error(err.Error(), "failed to translate xds ir")
					errChan <- err
				}

				// xDS translation is done in a best-effort manner, so the result
				// may contain partial resources even if there are errors.
				if result == nil {
					r.Logger.Info("no xds resources to publish")
					return
				}

				// Publish
				r.Xds.Store(key, result)

			}
		},
	)
	r.Logger.Info("subscriber shutting down")
}
