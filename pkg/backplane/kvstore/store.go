package kvstore

import (
	"context"

	"github.com/buraksezer/olric"
	"github.com/buraksezer/olric/config"
)

const (
	PubSubChannel = "_apoxy_pubsub"
)

type Store struct {
	k8sNamespace     string
	k8sLabelSelector string

	db *olric.Olric
}

// New creates a new kvstore instance.
func New(namespace, labelSelector string) *Store {
	return &Store{
		k8sNamespace:     namespace,
		k8sLabelSelector: labelSelector,
	}
}

// Start starts the kvstore. It returns an error if the kvstore fails to start.
// Uses background context created by New() method.
func (s *Store) Start(started chan struct{}) error {
	cfg := config.New("lan")
	cfg.ServiceDiscovery = NewK8sServiceDiscovery(
		s.k8sNamespace,
		s.k8sLabelSelector,
	)
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

func (s *Store) NewPubSub() (*olric.PubSub, error) {
	return s.db.NewEmbeddedClient().NewPubSub()
}
