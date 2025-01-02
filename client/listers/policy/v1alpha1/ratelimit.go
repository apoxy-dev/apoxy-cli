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

package v1alpha1

import (
	v1alpha1 "github.com/apoxy-dev/apoxy-cli/api/policy/v1alpha1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
)

// RateLimitLister helps list RateLimits.
// All objects returned here must be treated as read-only.
type RateLimitLister interface {
	// List lists all RateLimits in the indexer.
	// Objects returned here must be treated as read-only.
	List(selector labels.Selector) (ret []*v1alpha1.RateLimit, err error)
	// Get retrieves the RateLimit from the index for a given name.
	// Objects returned here must be treated as read-only.
	Get(name string) (*v1alpha1.RateLimit, error)
	RateLimitListerExpansion
}

// rateLimitLister implements the RateLimitLister interface.
type rateLimitLister struct {
	indexer cache.Indexer
}

// NewRateLimitLister returns a new RateLimitLister.
func NewRateLimitLister(indexer cache.Indexer) RateLimitLister {
	return &rateLimitLister{indexer: indexer}
}

// List lists all RateLimits in the indexer.
func (s *rateLimitLister) List(selector labels.Selector) (ret []*v1alpha1.RateLimit, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v1alpha1.RateLimit))
	})
	return ret, err
}

// Get retrieves the RateLimit from the index for a given name.
func (s *rateLimitLister) Get(name string) (*v1alpha1.RateLimit, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v1alpha1.Resource("ratelimit"), name)
	}
	return obj.(*v1alpha1.RateLimit), nil
}
