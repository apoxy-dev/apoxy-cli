package kvstore

import (
	"context"
	"fmt"
	"strings"

	"github.com/buraksezer/olric"
	"github.com/buraksezer/olric/config"
)

type Store struct {
	db *olric.Olric
}

// New creates a new kvstore instance.
func New(labelSelector string) (*Store, error) {
	selectorMap := map[string]string{}
	if labelSelector != "" {
		ss := strings.Split(labelSelector, ",")
		for _, s := range ss {
			kv := strings.Split(s, "=")
			if len(kv) != 2 {
				return nil, fmt.Errorf("invalid label selector: %s", labelSelector)
			}
			selectorMap[kv[0]] = kv[1]
		}
	}
	cfg := config.New("lan")
	if len(selectorMap) > 0 {
		cfg.ServiceDiscovery = NewK8sServiceDiscovery(selectorMap)
	}

	db, err := olric.New(cfg)
	if err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

// Start starts the kvstore. It returns an error if the kvstore fails to start.
// Uses background context created by New() method.
func (k *Store) Start() error {
	return k.db.Start()
}

// Stop stops the kvstore.
func (k *Store) Stop(ctx context.Context) error {
	return k.db.Shutdown(ctx)
}

// NewDMap creates a new DMap.
func (k *Store) NewDMap(name string) (olric.DMap, error) {
	return k.db.NewEmbeddedClient().NewDMap(name)
}
