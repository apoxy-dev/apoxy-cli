// Code generated by lister-gen. DO NOT EDIT.

package v1

import (
	v1 "github.com/apoxy-dev/apoxy-cli/api/gateway/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// GatewayClassLister helps list GatewayClasses.
// All objects returned here must be treated as read-only.
type GatewayClassLister interface {
	// List lists all GatewayClasses in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1.GatewayClass, err error)
	// Get retrieves the GatewayClass from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1.GatewayClass, error)
	GatewayClassListerExpansion
}

// gatewayClassLister implements the GatewayClassLister interface.
type gatewayClassLister struct {
	indexer cache.Indexer
}

// NewGatewayClassLister returns a new GatewayClassLister.
func NewGatewayClassLister(indexer cache.Indexer) GatewayClassLister {
	return &gatewayClassLister{indexer: indexer}
}

// List lists all GatewayClasses in the indexer.
func (s *gatewayClassLister) List(selector labels.Selector) (ret []*v1.GatewayClass, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1.GatewayClass))
	})
	return ret, err
}

// Get retrieves the GatewayClass from the index for a given name.
func (s *gatewayClassLister) Get(name string) (*v1.GatewayClass, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1.Resource("gatewayclass"), name)
	}
	return obj.(*v1.GatewayClass), nil
}