package network

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"github.com/dgraph-io/badger/v4"
	goipam "github.com/metal-stack/go-ipam"
)

// BadgerStorage implements the goipam.Storage interface using BadgerDB as the backend.
type BadgerStorage struct {
	db *badger.DB
}

const (
	prefixKey    = "network"
	namespaceKey = "namespace"
	separator    = "/"
)

// buildPrefixKey builds a key for a prefix.
func buildPrefixKey(namespace, prefix string) string {
	return filepath.Join(prefixKey, namespace, prefix)
}

// buildNamespaceKey builds a key for a namespace.
func buildNamespaceKey(namespace string) string {
	return filepath.Join(namespaceKey, namespace)
}

// NewBadgerStorage creates a new goipam.Storage instance backed by BadgerDB.
func NewBadgerStorage(db *badger.DB) goipam.Storage {
	return &BadgerStorage{db: db}
}

// Name returns the storage backend name.
func (b *BadgerStorage) Name() string {
	return "badger"
}

// CreatePrefix creates a new prefix in the given namespace. Returns error if prefix already exists.
func (b *BadgerStorage) CreatePrefix(ctx context.Context, prefix goipam.Prefix, namespace string) (goipam.Prefix, error) {
	log.Debugf("Creating prefix %s in namespace %s", prefix.Cidr, namespace)

	key := buildPrefixKey(namespace, prefix.Cidr)

	err := b.db.Update(func(txn *badger.Txn) error {
		// Check if prefix already exists
		_, err := txn.Get([]byte(key))
		if err == nil {
			return fmt.Errorf("prefix already exists")
		}
		if err != badger.ErrKeyNotFound {
			return err
		}

		data, err := prefix.GobEncode()
		if err != nil {
			return err
		}

		return txn.Set([]byte(key), data)
	})

	if err != nil {
		return goipam.Prefix{}, err
	}
	return prefix, nil
}

// ReadPrefix retrieves a prefix from the given namespace.
func (b *BadgerStorage) ReadPrefix(ctx context.Context, prefix string, namespace string) (goipam.Prefix, error) {
	log.Debugf("Reading prefix %s in namespace %s", prefix, namespace)

	key := buildPrefixKey(namespace, prefix)
	var result goipam.Prefix

	err := b.db.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}

		return item.Value(func(val []byte) error {
			return result.GobDecode(val)
		})
	})

	if err == badger.ErrKeyNotFound {
		return goipam.Prefix{}, fmt.Errorf("prefix not found")
	}
	return result, err
}

// DeleteAllPrefixes removes all prefixes from the given namespace.
func (b *BadgerStorage) DeleteAllPrefixes(ctx context.Context, namespace string) error {
	log.Debugf("Deleting all prefixes in namespace %s", namespace)
	return b.db.Update(func(txn *badger.Txn) error {
		prefix := []byte(buildPrefixKey(namespace, ""))
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			err := txn.Delete(it.Item().Key())
			if err != nil {
				return err
			}
		}
		return nil
	})
}

// ReadAllPrefixes returns all prefixes from the given namespace.
func (b *BadgerStorage) ReadAllPrefixes(ctx context.Context, namespace string) (goipam.Prefixes, error) {
	log.Debugf("Reading all prefixes in namespace %s", namespace)
	var prefixes goipam.Prefixes

	err := b.db.View(func(txn *badger.Txn) error {
		prefix := []byte(buildPrefixKey(namespace, ""))
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var p goipam.Prefix
				if err := p.GobDecode(val); err != nil {
					return err
				}
				prefixes = append(prefixes, p)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return prefixes, err
}

// ReadAllPrefixCidrs returns all prefix CIDRs from the given namespace.
func (b *BadgerStorage) ReadAllPrefixCidrs(ctx context.Context, namespace string) ([]string, error) {
	log.Debugf("Reading all prefix CIDRs in namespace %s", namespace)
	var cidrs []string

	err := b.db.View(func(txn *badger.Txn) error {
		prefix := []byte(buildPrefixKey(namespace, ""))
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			item := it.Item()
			err := item.Value(func(val []byte) error {
				var p goipam.Prefix
				if err := p.GobDecode(val); err != nil {
					return err
				}
				cidrs = append(cidrs, p.Cidr)
				return nil
			})
			if err != nil {
				return err
			}
		}
		return nil
	})

	return cidrs, err
}

// UpdatePrefix updates an existing prefix in the given namespace.
func (b *BadgerStorage) UpdatePrefix(ctx context.Context, prefix goipam.Prefix, namespace string) (goipam.Prefix, error) {
	log.Debugf("Updating prefix %s in namespace %s", prefix.Cidr, namespace)
	key := buildPrefixKey(namespace, prefix.Cidr)

	err := b.db.Update(func(txn *badger.Txn) error {
		// Check if prefix exists
		_, err := txn.Get([]byte(key))
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("prefix not found")
		}
		if err != nil {
			return err
		}

		data, err := prefix.GobEncode()
		if err != nil {
			return err
		}

		return txn.Set([]byte(key), data)
	})

	if err != nil {
		return goipam.Prefix{}, err
	}
	return prefix, nil
}

// DeletePrefix removes a prefix from the given namespace.
func (b *BadgerStorage) DeletePrefix(ctx context.Context, prefix goipam.Prefix, namespace string) (goipam.Prefix, error) {
	key := buildPrefixKey(namespace, prefix.Cidr)

	err := b.db.Update(func(txn *badger.Txn) error {
		// Check if prefix exists and get its value
		_, err := txn.Get([]byte(key))
		if err == badger.ErrKeyNotFound {
			return fmt.Errorf("prefix not found")
		}
		if err != nil {
			return err
		}

		return txn.Delete([]byte(key))
	})

	if err != nil {
		return goipam.Prefix{}, err
	}
	return prefix, nil
}

// CreateNamespace creates a new namespace. Returns error if namespace already exists.
func (b *BadgerStorage) CreateNamespace(ctx context.Context, namespace string) error {
	key := buildNamespaceKey(namespace)

	return b.db.Update(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(key))
		if err == nil {
			return fmt.Errorf("namespace already exists")
		}
		if err != badger.ErrKeyNotFound {
			return err
		}

		return txn.Set([]byte(key), []byte{})
	})
}

// ListNamespaces returns all existing namespaces.
func (b *BadgerStorage) ListNamespaces(ctx context.Context) ([]string, error) {
	var namespaces []string

	err := b.db.View(func(txn *badger.Txn) error {
		prefix := []byte(namespaceKey + separator)
		opts := badger.DefaultIteratorOptions
		opts.Prefix = prefix

		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Seek(prefix); it.ValidForPrefix(prefix); it.Next() {
			key := string(it.Item().Key())
			namespace := strings.TrimPrefix(key, string(prefix))
			namespaces = append(namespaces, namespace)
		}
		return nil
	})

	return namespaces, err
}

// DeleteNamespace removes a namespace and all its prefixes.
func (b *BadgerStorage) DeleteNamespace(ctx context.Context, namespace string) error {
	// First delete all prefixes in the namespace
	if err := b.DeleteAllPrefixes(ctx, namespace); err != nil {
		return err
	}

	// Then delete the namespace itself
	key := buildNamespaceKey(namespace)
	return b.db.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// Close closes the underlying BadgerDB instance.
func (b *BadgerStorage) Close() error {
	return b.db.Close()
}
