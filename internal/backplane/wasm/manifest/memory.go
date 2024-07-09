package manifest

import (
	"context"
	"fmt"
	"sync"

	extism "github.com/extism/go-sdk"
)

type memory struct {
	m sync.Map
}

// NewMemory creates a new memory provider.
func NewMemory() *memory {
	return &memory{}
}

func (m *memory) Get(ctx context.Context, host string) (*extism.Manifest, error) {
	if v, ok := m.m.Load(host); ok {
		return v.(*extism.Manifest), nil
	}
	return nil, fmt.Errorf("manifest not found")
}

func (m *memory) Set(ctx context.Context, name string, opts ...Option) error {
	manifest := newManifestWithOptions(opts...)
	m.m.Store(name, manifest)
	return nil
}

func (m *memory) Exists(ctx context.Context, name string) bool {
	_, ok := m.m.Load(name)
	return ok
}

func (m *memory) Delete(ctx context.Context, name string) error {
	m.m.Delete(name)
	return nil
}
