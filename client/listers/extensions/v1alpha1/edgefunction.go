// Code generated by lister-gen. DO NOT EDIT.

package v1alpha1

import (
	v1alpha1 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// EdgeFunctionLister helps list EdgeFunctions.
// All objects returned here must be treated as read-only.
type EdgeFunctionLister interface {
	// List lists all EdgeFunctions in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.EdgeFunction, err error)
	// Get retrieves the EdgeFunction from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.EdgeFunction, error)
	EdgeFunctionListerExpansion
}

// edgeFunctionLister implements the EdgeFunctionLister interface.
type edgeFunctionLister struct {
	indexer cache.Indexer
}

// NewEdgeFunctionLister returns a new EdgeFunctionLister.
func NewEdgeFunctionLister(indexer cache.Indexer) EdgeFunctionLister {
	return &edgeFunctionLister{indexer: indexer}
}

// List lists all EdgeFunctions in the indexer.
func (s *edgeFunctionLister) List(selector labels.Selector) (ret []*v1alpha1.EdgeFunction, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.EdgeFunction))
	})
	return ret, err
}

// Get retrieves the EdgeFunction from the index for a given name.
func (s *edgeFunctionLister) Get(name string) (*v1alpha1.EdgeFunction, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("edgefunction"), name)
	}
	return obj.(*v1alpha1.EdgeFunction), nil
}