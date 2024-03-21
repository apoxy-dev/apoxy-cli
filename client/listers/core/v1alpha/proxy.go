// Code generated by lister-gen. DO NOT EDIT.

package v1alpha

import (
	v1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// ProxyLister helps list Proxies.
// All objects returned here must be treated as read-only.
type ProxyLister interface {
	// List lists all Proxies in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha.Proxy, err error)
	// Get retrieves the Proxy from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha.Proxy, error)
	ProxyListerExpansion
}

// proxyLister implements the ProxyLister interface.
type proxyLister struct {
	indexer cache.Indexer
}

// NewProxyLister returns a new ProxyLister.
func NewProxyLister(indexer cache.Indexer) ProxyLister {
	return &proxyLister{indexer: indexer}
}

// List lists all Proxies in the indexer.
func (s *proxyLister) List(selector labels.Selector) (ret []*v1alpha.Proxy, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha.Proxy))
	})
	return ret, err
}

// Get retrieves the Proxy from the index for a given name.
func (s *proxyLister) Get(name string) (*v1alpha.Proxy, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha.Resource("proxy"), name)
	}
	return obj.(*v1alpha.Proxy), nil
}