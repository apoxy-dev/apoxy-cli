package kvstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/buraksezer/olric"
	"github.com/buraksezer/olric/config"
)

type Store struct {
	selectorMap map[string]string
	db          *olric.Olric
}

// New creates a new kvstore instance.
func New(labelSelector string) (*Store, error) {
	store := &Store{
		selectorMap: map[string]string{},
	}
	if labelSelector != "" {
		ss := strings.Split(labelSelector, ",")
		for _, s := range ss {
			kv := strings.Split(s, "=")
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid label selector: %s", labelSelector)
			}
			store.selectorMap[kv[0]] = kv[1]
		}
	}
	return store, nil
}

// Start starts the kvstore. It returns an error if the kvstore fails to start.
// Uses background context created by New() method.
func (s *Store) Start(started chan struct{}) error {
	cfg := config.New("lan")
	if len(s.selectorMap) > 0 {
		cfg.ServiceDiscovery = NewK8sServiceDiscovery(s.selectorMap)
	}
	cfg.Started = func() {
		if started != nil {
			close(started)
		}
	}

	db, err := olric.New(cfg)
	if err != nil {
		return err
	}
	s.db = db

	return s.db.Start()
}

// Stop stops the kvstore.
func (s *Store) Stop(ctx context.Context) error {
	return s.db.Shutdown(ctx)
}

// NewDMap creates a new DMap.
func (s *Store) NewDMap(name string) (olric.DMap, error) {
	return s.db.NewEmbeddedClient().NewDMap(name)
}
