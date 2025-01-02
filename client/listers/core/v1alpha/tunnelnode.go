/*
Copyright 2025 Apoxy, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
// Code generated by lister-gen. DO NOT EDIT.

package v1alpha

import (
	v1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// TunnelNodeLister helps list TunnelNodes.
// All objects returned here must be treated as read-only.
type TunnelNodeLister interface {
	// List lists all TunnelNodes in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha.TunnelNode, err error)
	// Get retrieves the TunnelNode from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha.TunnelNode, error)
	TunnelNodeListerExpansion
}

// tunnelNodeLister implements the TunnelNodeLister interface.
type tunnelNodeLister struct {
	indexer cache.Indexer
}

// NewTunnelNodeLister returns a new TunnelNodeLister.
func NewTunnelNodeLister(indexer cache.Indexer) TunnelNodeLister {
	return &tunnelNodeLister{indexer: indexer}
}

// List lists all TunnelNodes in the indexer.
func (s *tunnelNodeLister) List(selector labels.Selector) (ret []*v1alpha.TunnelNode, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha.TunnelNode))
	})
	return ret, err
}

// Get retrieves the TunnelNode from the index for a given name.
func (s *tunnelNodeLister) Get(name string) (*v1alpha.TunnelNode, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha.Resource("tunnelnode"), name)
	}
	return obj.(*v1alpha.TunnelNode), nil
}
