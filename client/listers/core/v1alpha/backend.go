// Code generated by lister-gen. DO NOT EDIT.

package v1alpha

import (
	v1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// BackendLister helps list Backends.
// All objects returned here must be treated as read-only.
type BackendLister interface {
	// List lists all Backends in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha.Backend, err error)
	// Get retrieves the Backend from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha.Backend, error)
	BackendListerExpansion
}

// backendLister implements the BackendLister interface.
type backendLister struct {
	indexer cache.Indexer
}

// NewBackendLister returns a new BackendLister.
func NewBackendLister(indexer cache.Indexer) BackendLister {
	return &backendLister{indexer: indexer}
}

// List lists all Backends in the indexer.
func (s *backendLister) List(selector labels.Selector) (ret []*v1alpha.Backend, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha.Backend))
	})
	return ret, err
}

// Get retrieves the Backend from the index for a given name.
func (s *backendLister) Get(name string) (*v1alpha.Backend, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha.Resource("backend"), name)
	}
	return obj.(*v1alpha.Backend), nil
}