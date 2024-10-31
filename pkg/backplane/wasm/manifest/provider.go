// Package manifest implements Edge Function Manifest utilities.
package manifest

import (
	"context"

	extism "github.com/extism/go-sdk"
)

// Provider is an interface for getting a manifest.
type Provider interface {
	Get(ctx context.Context, name string) (*extism.Manifest, error)
}
