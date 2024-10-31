package manifest

import (
	"context"
	"fmt"

	extism "github.com/extism/go-sdk"
)

type localPathProvider struct {
	paths map[string]string
}

// NewLocalPathProvider creates a new local manifest provider.
func NewLocalPathProvider(
	paths map[string]string,
) Provider {
	return &localPathProvider{paths: paths}
}

// Get returns the manifest for the given name.
func (p *localPathProvider) Get(ctx context.Context, name string) (*extism.Manifest, error) {
	path, ok := p.paths[name]
	if !ok {
		return nil, fmt.Errorf("manifest not found: %s", name)
	}
	return &extism.Manifest{
		Wasm: []extism.Wasm{
			extism.WasmFile{
				Path: path,
			},
		},
		Config: map[string]string{},
	}, nil
}
