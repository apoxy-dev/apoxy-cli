package manifest

import (
	"context"

	extism "github.com/extism/go-sdk"
)

type Option func(*options)

type Store interface {
	// Set sets the manifest for the given name.
	Set(ctx context.Context, name string, opts ...Option) error

	// Exists checks if the manifest exists for the given name.
	Exists(ctx context.Context, name string) bool

	// Delete deletes the manifest for the given name.
	Delete(ctx context.Context, name string) error
}

type options struct {
	wasm extism.Wasm
}

func defaultOptions() *options {
	return &options{}
}

// WithWasmData sets the wasm data for the manifest.
func WithWasmData(data []byte) Option {
	return func(o *options) {
		o.wasm = extism.WasmData{
			Name: "main.wasm",
			Data: data,
		}
	}
}

func newManifestWithOptions(opts ...Option) *extism.Manifest {
	o := defaultOptions()
	for _, opt := range opts {
		opt(o)
	}

	return &extism.Manifest{
		Wasm: []extism.Wasm{o.wasm},
	}
}
