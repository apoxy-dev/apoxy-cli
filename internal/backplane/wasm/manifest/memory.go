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

// NewMemoryProvider creates a new memory provider.
func NewMemoryProvider() Provider {
	return &memory{}
}

func (m *memory) Get(ctx context.Context, host string) (*extism.Manifest, error) {
	if v, ok := m.m.Load(host); ok {
		return v.(*extism.Manifest), nil
	}
	return nil, fmt.Errorf("manifest not found")
}

func (m *memory) Set(host string, manifest *extism.Manifest) error {
	m.m.Store(host, manifest)
	return nil
}
